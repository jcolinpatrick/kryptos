#!/usr/bin/env python3
"""
KryptosBot Campaign V3 — Analyst-Oracle-Feedback Loop.

Replaces V2's Polybius-only sandbox approach with a three-layer design:
  Layer 1: ANALYST  — Opus reasons about evidence, generates ranked hypotheses
  Layer 2: ORACLE   — Local compute tests hypotheses (free, 28 cores)
  Layer 3: FEEDBACK — Results feed back to Opus with structured scoring

Key principle: Opus REASONS, CPUs COMPUTE.

Usage:
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py --budget 100
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py --local-only
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py --dry-run
    PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py --phase briefing
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, STORE_THRESHOLD, SIGNAL_THRESHOLD

from kryptosbot.analyst_prompts import (
    SYSTEM_PROMPT,
    PHASE_BRIEFING,
    PHASE_SCHEIDT,
    PHASE_PLAINTEXT,
    PHASE_ANOMALIES,
    HYPOTHESIS_GENERATION,
    FEEDBACK_TEMPLATE,
    STAGNATION_BREAKER,
    CONVERGENCE_PROMPT,
    build_evidence_package,
)
from kryptosbot.oracle import dispatch_hypothesis, format_results_for_feedback

logger = logging.getLogger("kryptosbot.campaign_v3")

PROJECT_ROOT = _ROOT
CAMPAIGN_DIR = PROJECT_ROOT / "results" / "campaign_v3"
STATE_FILE = CAMPAIGN_DIR / "state.json"


# ---------------------------------------------------------------------------
# Campaign state
# ---------------------------------------------------------------------------

@dataclass
class CampaignState:
    """Persistent state for V3 campaign."""
    version: str = "3.0"
    budget_total: float = 100.0
    budget_spent: float = 0.0
    model: str = "claude-opus-4-6"
    started_at: str = ""
    last_round_at: str = ""

    # Phase completion
    phase_status: dict[str, str] = field(default_factory=dict)
    phase_results: dict[str, dict] = field(default_factory=dict)

    # Opus loop
    rounds_completed: int = 0
    total_hypotheses_tested: int = 0
    conversation_history: list[dict] = field(default_factory=list)

    # Research journal
    journal_insights: list[str] = field(default_factory=list)
    journal_dead_ends: list[str] = field(default_factory=list)
    journal_promising: list[dict] = field(default_factory=list)
    journal_hypotheses: list[dict] = field(default_factory=list)
    stagnation_counter: int = 0

    # Best results
    best_crib_score: int = 0
    best_method: str = ""
    best_plaintext: str = ""

    @property
    def budget_remaining(self) -> float:
        return max(0.0, self.budget_total - self.budget_spent)

    def is_phase_done(self, name: str) -> bool:
        return self.phase_status.get(name) == "done"

    def mark_phase_done(self, name: str, result: dict) -> None:
        self.phase_status[name] = "done"
        self.phase_results[name] = result


def load_state() -> CampaignState:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            return CampaignState(**{
                k: v for k, v in data.items()
                if k in CampaignState.__dataclass_fields__
            })
        except Exception as e:
            logger.error("Failed to load state: %s (starting fresh)", e)
    return CampaignState(started_at=datetime.now(timezone.utc).isoformat())


def save_state(state: CampaignState) -> None:
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    state.last_round_at = datetime.now(timezone.utc).isoformat()
    data = asdict(state)
    # Trim large lists to prevent state bloat
    data["journal_hypotheses"] = data["journal_hypotheses"][-200:]
    data["journal_insights"] = data["journal_insights"][-100:]
    data["journal_dead_ends"] = data["journal_dead_ends"][-100:]
    data["conversation_history"] = data["conversation_history"][-12:]
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.rename(STATE_FILE)
    except Exception:
        STATE_FILE.write_text(json.dumps(data, indent=2, default=str))


# ---------------------------------------------------------------------------
# System prompt blocks (cached across rounds)
# ---------------------------------------------------------------------------

def _build_system_blocks(evidence: str) -> list[dict]:
    """Build system prompt blocks with evidence package for prompt caching."""
    return [
        {
            "type": "text",
            "text": SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        },
        {
            "type": "text",
            "text": evidence,
            "cache_control": {"type": "ephemeral"},
        },
    ]


# ---------------------------------------------------------------------------
# Phase 1: Evidence Briefing
# ---------------------------------------------------------------------------

def run_briefing(state: CampaignState, client: Any, system_blocks: list[dict]) -> dict:
    """Phase 1: Feed Opus the full evidence package for situation assessment."""
    if state.is_phase_done("briefing"):
        print("  Phase 1 (briefing): already done, skipping")
        return state.phase_results.get("briefing", {})

    print("\n" + "=" * 70)
    print("  PHASE 1: Evidence Briefing")
    print("=" * 70)

    result = client.reason_about(
        PHASE_BRIEFING,
        max_tokens=8192,
        system_override=system_blocks,
    )

    if result and not result.get("raw_text"):
        print(f"  Assessment received: {len(str(result))} chars")
        if "top_3_hypotheses" in result:
            for h in result["top_3_hypotheses"]:
                print(f"    - {h.get('name', '?')}: {h.get('description', '')[:80]}")
        if "key_insight" in result:
            print(f"  Key insight: {result['key_insight'][:200]}")
            state.journal_insights.append(f"[Briefing] {result['key_insight']}")
    else:
        print(f"  Raw response (JSON parse failed): {str(result)[:200]}...")

    state.mark_phase_done("briefing", result or {})
    save_state(state)
    return result or {}


# ---------------------------------------------------------------------------
# Phase 2: Scheidt Philosophy Alignment
# ---------------------------------------------------------------------------

def run_scheidt_alignment(state: CampaignState, client: Any, system_blocks: list[dict]) -> dict:
    """Phase 2: Reason about Scheidt's crypto philosophy."""
    if state.is_phase_done("scheidt"):
        print("  Phase 2 (scheidt): already done, skipping")
        return state.phase_results.get("scheidt", {})

    print("\n" + "=" * 70)
    print("  PHASE 2: Scheidt Philosophy Alignment")
    print("=" * 70)

    result = client.reason_about(
        PHASE_SCHEIDT,
        max_tokens=8192,
        system_override=system_blocks,
    )

    if result:
        candidates = result.get("archetype_candidates", [])
        print(f"  {len(candidates)} archetype candidates:")
        for c in candidates:
            print(f"    - {c.get('name', '?')}: {c.get('how_it_works', '')[:80]}")
        if result.get("key_prediction"):
            print(f"  Key prediction: {result['key_prediction'][:200]}")
            state.journal_insights.append(f"[Scheidt] {result['key_prediction']}")

    state.mark_phase_done("scheidt", result or {})
    save_state(state)
    return result or {}


# ---------------------------------------------------------------------------
# Phase 3: Plaintext Narrative Inference
# ---------------------------------------------------------------------------

def run_plaintext_inference(state: CampaignState, client: Any, system_blocks: list[dict]) -> dict:
    """Phase 3: Generate candidate plaintext from narrative reasoning."""
    if state.is_phase_done("plaintext"):
        print("  Phase 3 (plaintext): already done, skipping")
        return state.phase_results.get("plaintext", {})

    print("\n" + "=" * 70)
    print("  PHASE 3: Plaintext Narrative Inference")
    print("=" * 70)

    result = client.reason_about(
        PHASE_PLAINTEXT,
        max_tokens=8192,
        system_override=system_blocks,
    )

    if result:
        for section in ("pre_ene_candidates", "mid_section_candidates",
                        "post_bc_candidates", "full_97_attempts"):
            candidates = result.get(section, [])
            if candidates:
                print(f"  {section}: {len(candidates)} candidates")
                for c in candidates[:3]:
                    text = c.get("text", "")[:40]
                    conf = c.get("confidence", 0)
                    print(f"    - {text}... (conf={conf})")
        if result.get("narrative_theory"):
            print(f"  Theory: {result['narrative_theory'][:200]}")
            state.journal_insights.append(f"[Plaintext] {result['narrative_theory'][:200]}")

    state.mark_phase_done("plaintext", result or {})
    save_state(state)
    return result or {}


# ---------------------------------------------------------------------------
# Phase 4: Anomaly-Driven Hypothesis Generation
# ---------------------------------------------------------------------------

def run_anomaly_synthesis(state: CampaignState, client: Any, system_blocks: list[dict]) -> dict:
    """Phase 4: Analyze physical anomalies for coherent signals."""
    if state.is_phase_done("anomalies"):
        print("  Phase 4 (anomalies): already done, skipping")
        return state.phase_results.get("anomalies", {})

    print("\n" + "=" * 70)
    print("  PHASE 4: Anomaly Synthesis")
    print("=" * 70)

    result = client.reason_about(
        PHASE_ANOMALIES,
        max_tokens=8192,
        system_override=system_blocks,
    )

    if result:
        signals = result.get("signal_anomalies", [])
        noise = result.get("noise_anomalies", [])
        print(f"  Signal anomalies: {len(signals)}, Noise: {len(noise)}")
        for s in signals[:5]:
            print(f"    SIGNAL: {s.get('anomaly', '?')} — {s.get('interpretation', '')[:80]}")
        if result.get("the_point_interpretation"):
            print(f"  'The point': {result['the_point_interpretation'][:200]}")
            state.journal_insights.append(
                f"[Anomaly] The point = {result['the_point_interpretation'][:200]}"
            )
        if result.get("key_prediction"):
            state.journal_insights.append(f"[Anomaly] {result['key_prediction'][:200]}")

    state.mark_phase_done("anomalies", result or {})
    save_state(state)
    return result or {}


# ---------------------------------------------------------------------------
# Phase 5: Iterative Hypothesis-Test Loop
# ---------------------------------------------------------------------------

def run_hypothesis_loop(
    state: CampaignState,
    client: Any,
    system_blocks: list[dict],
    max_rounds: int = 50,
) -> None:
    """Phase 5: Generate → Dispatch → Score → Feedback loop."""
    print("\n" + "=" * 70)
    print("  PHASE 5: Iterative Hypothesis-Test Loop")
    print(f"  Budget remaining: ${state.budget_remaining:.2f}")
    print("=" * 70)

    # Build context from prior phase results
    phase_context_parts = []
    for phase_name in ("briefing", "scheidt", "plaintext", "anomalies"):
        pr = state.phase_results.get(phase_name, {})
        if pr and not pr.get("raw_text"):
            # Summarize key findings
            if phase_name == "briefing" and pr.get("key_insight"):
                phase_context_parts.append(f"Briefing insight: {pr['key_insight']}")
            elif phase_name == "scheidt":
                for c in pr.get("archetype_candidates", [])[:3]:
                    phase_context_parts.append(
                        f"Scheidt archetype: {c.get('name', '?')} — {c.get('how_it_works', '')[:100]}"
                    )
            elif phase_name == "plaintext" and pr.get("narrative_theory"):
                phase_context_parts.append(f"Narrative: {pr['narrative_theory'][:200]}")
            elif phase_name == "anomalies" and pr.get("the_point_interpretation"):
                phase_context_parts.append(f"The point: {pr['the_point_interpretation'][:200]}")

    phase_context = "\n".join(phase_context_parts) if phase_context_parts else "(no prior phase context)"

    round_num = state.rounds_completed

    while round_num < max_rounds and not _shutdown_requested:
        round_num += 1

        remaining = state.budget_remaining - (client.usage.cost_usd if client else 0)
        if remaining <= 0:
            print(f"\n  Budget exhausted (${state.budget_spent:.2f}/${state.budget_total:.2f})")
            break

        cost_so_far = state.budget_spent + (client.usage.cost_usd if client else 0)
        print(f"\n{'─' * 70}")
        print(f"  Round {round_num} — ${cost_so_far:.2f}/${state.budget_total:.2f} "
              f"| stagnation={state.stagnation_counter}")
        print(f"{'─' * 70}")

        # Build prompt
        if state.stagnation_counter >= 5:
            prompt = STAGNATION_BREAKER.format(n=state.stagnation_counter)
            state.stagnation_counter = 0  # Reset after breaker
        else:
            # Build feedback from last round if available
            dead_ends_str = "\n".join(f"  - {d}" for d in state.journal_dead_ends[-10:])
            insights_str = "\n".join(f"  - {i}" for i in state.journal_insights[-10:])
            promising_str = "\n".join(
                f"  - {p.get('name', '?')}: score={p.get('score', 0)}"
                for p in state.journal_promising[-5:]
            )

            prompt = f"""## Phase Context
{phase_context}

## Key Insights So Far
{insights_str or '(none yet)'}

## Dead Ends (do not revisit)
{dead_ends_str or '(none yet)'}

## Promising Leads
{promising_str or '(none yet)'}

{HYPOTHESIS_GENERATION}"""

        # Generate hypotheses
        print(f"  [Opus] Generating hypotheses...")
        hypotheses = client.generate_hypotheses_v3(
            prompt,
            max_tokens=8192,
            system_override=system_blocks,
        )

        if not hypotheses:
            print("    No hypotheses generated. Continuing...")
            state.stagnation_counter += 1
            state.rounds_completed = round_num
            save_state(state)
            continue

        print(f"  {len(hypotheses)} hypotheses:")
        for h in hypotheses:
            print(f"    - [{h.get('type', '?')}] {h.get('name', '?')}")

        # Test each hypothesis via Oracle
        round_results = []
        any_progress = False
        for h in hypotheses:
            if _shutdown_requested:
                break
            h_name = h.get("name", "unknown")
            print(f"\n  [Oracle] Testing: {h_name}...")
            result = dispatch_hypothesis(h)
            round_results.append(result)

            verdict = result.get("verdict", "?")
            print(f"    → {verdict}", end="")
            if result.get("crib_score"):
                print(f" (crib={result['crib_score']}/24)", end="")
            if result.get("best_matches"):
                print(f" (key={result['best_matches']}/24)", end="")
            if result.get("f1_score"):
                print(f" (F1={result['f1_score']:.3f})", end="")
            if result.get("error"):
                print(f" ERROR: {result['error'][:60]}", end="")
            print(f" [{result.get('elapsed_seconds', 0):.1f}s]")

            # Update journal
            state.journal_hypotheses.append({
                "round": round_num,
                "name": h_name,
                "type": h.get("type", ""),
                "verdict": verdict,
            })

            # Track progress
            score = result.get("crib_score", result.get("best_matches", 0))
            if score and score > state.best_crib_score:
                state.best_crib_score = score
                state.best_method = h_name
                state.best_plaintext = result.get("text", result.get("plaintext_preview", ""))[:200]
                any_progress = True

            if verdict in ("SIGNAL", "STRONG", "INTERESTING"):
                state.journal_promising.append({
                    "name": h_name, "score": score,
                    "round": round_num, "type": h.get("type", ""),
                })
                any_progress = True

                # Convergence mode
                if score >= SIGNAL_THRESHOLD:
                    print(f"\n  *** SIGNAL DETECTED: {h_name} score={score}/24 ***")
                    _run_convergence(state, client, system_blocks, h, result, round_num)

            elif verdict == "NOISE" and h.get("type") != "structural_insight":
                desc = h.get("description", h_name)[:200]
                if desc not in state.journal_dead_ends:
                    state.journal_dead_ends.append(desc)

        # Feed results back to Opus
        if round_results and not _shutdown_requested:
            feedback_text = format_results_for_feedback(round_results)
            # The feedback is included in the next round's context via conversation history

        # Stagnation tracking
        if not any_progress:
            state.stagnation_counter += 1
        else:
            state.stagnation_counter = 0

        # Update state
        if client:
            state.budget_spent += client.usage.cost_usd
            client.usage = type(client.usage)(model=client.model)
            client.budget_usd = state.budget_remaining
            state.conversation_history = list(client._conversation_history[-12:])
        state.total_hypotheses_tested += len(round_results)
        state.rounds_completed = round_num
        save_state(state)

        print(f"\n  Round {round_num} complete: {len(round_results)} tested, "
              f"best={state.best_crib_score}/24, stagnation={state.stagnation_counter}")


def _run_convergence(
    state: CampaignState,
    client: Any,
    system_blocks: list[dict],
    hypothesis: dict,
    result: dict,
    round_num: int,
) -> None:
    """When a hypothesis scores above noise, enter convergence mode."""
    print("\n" + "=" * 70)
    print("  CONVERGENCE MODE — Refining signal")
    print("=" * 70)

    prompt = CONVERGENCE_PROMPT.format(
        score=result.get("crib_score", result.get("best_matches", 0)),
        hypothesis_name=hypothesis.get("name", "unknown"),
        method_description=hypothesis.get("description", "")[:300],
        matched_positions=str(result.get("matched_positions", "?")),
        mismatched_positions=str(result.get("mismatch_details", result.get("mismatches", "?")))[:500],
        keystream_fragment=str(result.get("keystream_fragment", "?")),
    )

    variations = client.generate_hypotheses_v3(
        prompt,
        max_tokens=8192,
        system_override=system_blocks,
    )

    if variations:
        print(f"  {len(variations)} targeted variations generated")
        for v in variations:
            v_name = v.get("name", "unknown")
            print(f"  [Oracle] Testing variation: {v_name}...")
            v_result = dispatch_hypothesis(v)
            verdict = v_result.get("verdict", "?")
            score = v_result.get("crib_score", v_result.get("best_matches", 0))
            print(f"    → {verdict} (score={score})")

            if score and score > state.best_crib_score:
                state.best_crib_score = score
                state.best_method = v_name
                any_text = v_result.get("text", v_result.get("plaintext_preview", ""))
                state.best_plaintext = any_text[:200]

            state.journal_hypotheses.append({
                "round": round_num, "name": f"convergence/{v_name}",
                "type": v.get("type", ""), "verdict": verdict,
            })


# ---------------------------------------------------------------------------
# Main campaign runner
# ---------------------------------------------------------------------------

_shutdown_requested = False
_main_pid = None


def _signal_handler(signum, frame):
    global _shutdown_requested
    if os.getpid() != _main_pid:
        return
    if not _shutdown_requested:
        _shutdown_requested = True
        print("\n  Shutdown requested — finishing current round...")


def _load_api_key() -> str | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        return api_key
    for env_file in [Path(__file__).parent / ".env", _ROOT / ".env"]:
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if line.startswith("ANTHROPIC_API_KEY="):
                    return line.split("=", 1)[1].strip()
    return None


def run_campaign(
    *,
    budget: float = 100.0,
    model: str = "claude-opus-4-6",
    local_only: bool = False,
    dry_run: bool = False,
    phase: str = "",
) -> None:
    """Main campaign entry point."""
    global _shutdown_requested, _main_pid

    _main_pid = os.getpid()
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    state = load_state()
    state.budget_total = budget
    state.model = model

    if not state.started_at:
        state.started_at = datetime.now(timezone.utc).isoformat()

    print(f"\n{'=' * 70}")
    print(f"  KryptosBot Campaign V3 — Analyst-Oracle-Feedback Loop")
    print(f"{'=' * 70}")
    print(f"  Model:     {model}")
    print(f"  Budget:    ${state.budget_spent:.2f} / ${state.budget_total:.2f}")
    print(f"  Rounds:    {state.rounds_completed}")
    print(f"  Best:      crib={state.best_crib_score}/24 ({state.best_method})")
    print(f"  Insights:  {len(state.journal_insights)}")
    phases_done = sum(1 for v in state.phase_status.values() if v == "done")
    print(f"  Phases:    {phases_done}/4 done")
    print(f"{'=' * 70}")

    # Load evidence package
    print("\n  Loading evidence package...")
    evidence = build_evidence_package()
    evidence_size = len(evidence)
    print(f"  Evidence: {evidence_size:,} chars (~{evidence_size // 4:,} tokens)")

    if dry_run:
        print("\n  [DRY RUN] Phase plan:")
        for p_name in ("briefing", "scheidt", "plaintext", "anomalies"):
            status = state.phase_status.get(p_name, "pending")
            print(f"    {p_name}: {status}")
        print(f"    hypothesis_loop: {'pending' if state.rounds_completed == 0 else f'{state.rounds_completed} rounds'}")
        _print_summary(state)
        return

    if local_only:
        print("\n  [LOCAL ONLY] Evidence loaded. No API calls.")
        # Test Oracle with a simple hypothesis
        from kryptosbot.oracle import test_full_plaintext
        test_pt = "A" * CT_LEN
        test_result = test_full_plaintext(test_pt)
        print(f"  Oracle smoke test: crib_score={test_result.get('crib_score', '?')}/24 (should be 0)")
        _print_summary(state)
        return

    # Initialize API client
    api_key = _load_api_key()
    if not api_key:
        print("  ERROR: No ANTHROPIC_API_KEY found.")
        print("  Set in environment or .env file.")
        return

    from kryptosbot.api_client import KryptosAPIClient

    client = KryptosAPIClient(
        api_key=api_key,
        model=model,
        budget_usd=state.budget_remaining,
        conversation_mode=True,
    )

    system_blocks = _build_system_blocks(evidence)

    # Phase dispatch
    phase_map = {
        "briefing": run_briefing,
        "scheidt": run_scheidt_alignment,
        "plaintext": run_plaintext_inference,
        "anomalies": run_anomaly_synthesis,
    }

    if phase and phase in phase_map:
        phase_map[phase](state, client, system_blocks)
        state.budget_spent += client.usage.cost_usd
        save_state(state)
        _print_summary(state)
        return

    # Run all phases sequentially
    try:
        for p_name, p_fn in phase_map.items():
            if _shutdown_requested:
                break
            p_fn(state, client, system_blocks)

        # Phase 5: Hypothesis loop
        if not _shutdown_requested:
            run_hypothesis_loop(state, client, system_blocks)

    except Exception as e:
        logger.error("Campaign error: %s", e, exc_info=True)
        print(f"\n  ERROR: {e}")
    finally:
        if client:
            state.budget_spent += client.usage.cost_usd
            state.conversation_history = list(client._conversation_history[-12:])
        save_state(state)
        _print_summary(state)


def _print_summary(state: CampaignState) -> None:
    print(f"\n{'=' * 70}")
    print(f"  CAMPAIGN V3 SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Rounds completed:    {state.rounds_completed}")
    print(f"  Budget spent:        ${state.budget_spent:.2f} / ${state.budget_total:.2f}")
    print(f"  Hypotheses tested:   {state.total_hypotheses_tested}")
    print(f"  Best crib score:     {state.best_crib_score}/24")
    print(f"  Best method:         {state.best_method}")
    print(f"  Insights:            {len(state.journal_insights)}")

    print(f"\n  Phases:")
    for name in ("briefing", "scheidt", "plaintext", "anomalies"):
        status = state.phase_status.get(name, "pending")
        print(f"    {name}: {status}")

    if state.journal_insights:
        print(f"\n  Key Insights ({len(state.journal_insights)}):")
        for i in state.journal_insights[-5:]:
            print(f"    - {i[:120]}")

    if state.journal_promising:
        print(f"\n  Promising ({len(state.journal_promising)}):")
        for p in state.journal_promising[-5:]:
            print(f"    - {p.get('name', '?')}: score={p.get('score', 0)}")

    print(f"\n  State: {STATE_FILE}")
    print(f"  Resume: PYTHONPATH=src python3 -u kryptosbot/campaign_v2.py")
    print(f"{'=' * 70}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="campaign_v2.py",
        description="KryptosBot Campaign V3 — Analyst-Oracle-Feedback Loop",
    )
    parser.add_argument("--budget", type=float, default=100.0,
                        help="Total API budget in USD (default: $100)")
    parser.add_argument("--model", type=str, default="claude-opus-4-6",
                        choices=["claude-sonnet-4-6", "claude-opus-4-6"],
                        help="Model for reasoning")
    parser.add_argument("--local-only", action="store_true",
                        help="No API calls — load evidence and test Oracle only")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show campaign plan without running")
    parser.add_argument("--verbose", action="store_true",
                        help="Debug logging")
    parser.add_argument("--reset", action="store_true",
                        help="Reset campaign state (backs up old state)")
    parser.add_argument("--phase", type=str, default="",
                        choices=["", "briefing", "scheidt", "plaintext", "anomalies"],
                        help="Run only a specific reasoning phase")

    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.reset:
        if STATE_FILE.exists():
            backup = STATE_FILE.with_suffix(f".backup_{int(time.time())}.json")
            STATE_FILE.rename(backup)
            print(f"  State backed up to {backup.name}")

    run_campaign(
        budget=args.budget,
        model=args.model,
        local_only=args.local_only,
        dry_run=args.dry_run,
        phase=args.phase,
    )


if __name__ == "__main__":
    main()
