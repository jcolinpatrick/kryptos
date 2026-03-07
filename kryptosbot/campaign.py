#!/usr/bin/env python3
"""
KryptosBot Campaign Runner — Bean-guided partial transposition + evolutionary search.

Architecture (informed by Bean 2021):
    Phase 0: Built-in reading orders (first run only)
    Phase 1: Bean Baseline — identity decryption + Bean diagnostics
    Phase 2: Exhaustive single-swap search (C(97,2) = 4,656 per combo)
    Phase 3: Focused double-swap (top swap pairs from Phase 2)
    Phase 4: Near-identity hill-climbing (start from identity, find minimal swaps)
    Phase 5: API-guided hypothesis generation (with Bean context)
    Phase 6: Evolutionary crossover + depth refinement (recurring)

Key insight from Bean 2021: statistical evidence (p≈1/240 to 1/5520) says MOST
positions have direct one-to-one substitution. Instead of searching 97! full
permutations, we search for the FEW positions that might be transposed.

Usage:
    PYTHONPATH=src python3 -u kryptosbot/campaign.py
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --budget 50
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --local-only
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --dry-run
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --phase bean   # Run Bean phases only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import multiprocessing as mp
import os
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from kryptosbot.hypothesis_tester import (
    HypothesisResult,
    K4_LEN,
    PRIORITY_KEYWORDS,
    run_hillclimb,
    run_hillclimb_multi_keyword,
    test_all_hypotheses,
    test_hypothesis,
    # Bean-guided functions
    run_identity_and_bean_diagnostic,
    run_exhaustive_single_swap,
    run_near_identity_hillclimb,
    run_focused_double_swap,
    # Priority keyword sweep
    run_priority_keyword_sweep,
)

logger = logging.getLogger("kryptosbot.campaign")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGN_DIR = PROJECT_ROOT / "results" / "campaign"
STATE_FILE = CAMPAIGN_DIR / "state.json"

# --- Configuration ---
ELITE_SIZE = 100                # Top N permutations to keep
HILLCLIMB_ITERS = 50000        # Iterations per hill-climb restart
MULTI_KW_TOP_N = 3             # Hill-climb top N keyword combos per seed
OPUS_INSIGHT_INTERVAL = 25     # Opus analysis every N rounds
DEPTH_INTERVAL = 10            # Full multi-keyword sweep every N rounds
CROSSOVER_INTERVAL = 5         # Evolutionary crossover every N rounds
BREAKTHROUGH_CRIB_HITS = 10    # Crib hits that trigger breakthrough alert
STALE_CONVERSATION_ROUNDS = 50 # Reset conversation to avoid stale context

# Score thresholds
ELITE_ENTRY_SCORE = -700.0     # Min score to enter elite population
HILLCLIMB_TRIGGER = -650.0     # Auto hill-climb results above this


# ---------------------------------------------------------------------------
# Campaign state
# ---------------------------------------------------------------------------

@dataclass
class EliteMember:
    """A permutation in the elite population."""
    perm: list[int]
    score: float
    method: str
    plaintext: str
    crib_hits: int
    source: str              # How it was found
    round_found: int
    perm_hash: str = ""      # For dedup

    def __post_init__(self):
        if not self.perm_hash:
            self.perm_hash = _perm_hash(self.perm)


@dataclass
class CampaignState:
    """Persistent campaign state — survives restarts."""
    budget_total: float = 250.0
    budget_spent: float = 0.0
    rounds_completed: int = 0
    total_hypotheses_tested: int = 0
    total_candidates_tested: int = 0
    elite: list[dict] = field(default_factory=list)
    tried_hashes: list[str] = field(default_factory=list)
    conversation_history: list[dict] = field(default_factory=list)
    best_ever_score: float = -9999.0
    best_ever_crib_hits: int = 0
    best_ever_plaintext: str = ""
    best_ever_method: str = ""
    best_ever_perm: list[int] = field(default_factory=list)
    started_at: str = ""
    last_round_at: str = ""
    model: str = "claude-sonnet-4-6"
    # Bean-specific state
    bean_baseline_done: bool = False
    bean_single_swap_done: bool = False
    bean_double_swap_done: bool = False
    bean_near_identity_done: bool = False
    bean_hot_swaps: list[list[int]] = field(default_factory=list)
    bean_identity_top_score: float = -9999.0
    bean_best_swap_improvement: float = 0.0
    # Priority keyword sweep state
    priority_keyword_done: bool = False
    priority_keyword_results: dict = field(default_factory=dict)

    @property
    def budget_remaining(self) -> float:
        return max(0.0, self.budget_total - self.budget_spent)

    @property
    def elite_members(self) -> list[EliteMember]:
        return [EliteMember(**e) for e in self.elite]

    def add_elite(self, member: EliteMember) -> bool:
        """Add to elite if good enough. Returns True if added."""
        h = member.perm_hash
        for e in self.elite:
            if e.get("perm_hash") == h:
                if member.score > e["score"]:
                    e.update(asdict(member))
                    self._sort_elite()
                    return True
                return False

        if len(self.elite) < ELITE_SIZE or member.score > self.elite[-1]["score"]:
            self.elite.append(asdict(member))
            self._sort_elite()
            if len(self.elite) > ELITE_SIZE:
                self.elite = self.elite[:ELITE_SIZE]
            return True
        return False

    def _sort_elite(self):
        self.elite.sort(key=lambda e: e["score"], reverse=True)

    def update_best(self, score: float, crib_hits: int, plaintext: str,
                    method: str, perm: list[int]):
        if score > self.best_ever_score:
            self.best_ever_score = score
            self.best_ever_plaintext = plaintext
            self.best_ever_method = method
            self.best_ever_perm = perm
        if crib_hits > self.best_ever_crib_hits:
            self.best_ever_crib_hits = crib_hits


def _perm_hash(perm: list[int]) -> str:
    return hashlib.md5(json.dumps(perm).encode()).hexdigest()[:12]


def load_state() -> CampaignState:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text())
            state = CampaignState(**{
                k: v for k, v in data.items()
                if k in CampaignState.__dataclass_fields__
            })
            logger.info("Loaded campaign state: %d rounds, $%.2f spent, %d elite",
                        state.rounds_completed, state.budget_spent, len(state.elite))
            return state
        except Exception as e:
            logger.error("Failed to load state: %s (starting fresh)", e)
    return CampaignState(started_at=datetime.now(timezone.utc).isoformat())


def save_state(state: CampaignState) -> None:
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    state.last_round_at = datetime.now(timezone.utc).isoformat()
    data = asdict(state)
    data["tried_hashes"] = data["tried_hashes"][-50000:]
    try:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.rename(STATE_FILE)
    except Exception:
        STATE_FILE.write_text(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# Evolutionary crossover
# ---------------------------------------------------------------------------

def _crossover_pair(perm_a: list[int], perm_b: list[int]) -> list[int]:
    """Order crossover (OX1): take a segment from A, fill rest from B's order."""
    import random
    n = len(perm_a)
    start = random.randint(0, n - 2)
    end = random.randint(start + 1, n)

    child = [-1] * n
    segment = set()
    for i in range(start, end):
        child[i] = perm_a[i]
        segment.add(perm_a[i])

    b_order = [x for x in perm_b if x not in segment]
    j = 0
    for i in range(n):
        if child[i] == -1:
            child[i] = b_order[j]
            j += 1

    return child


def generate_crossover_hypotheses(
    elite: list[EliteMember],
    count: int = 20,
) -> list[dict]:
    """Generate crossover offspring from elite pairs."""
    import random
    if len(elite) < 2:
        return []

    hypotheses = []
    for i in range(count):
        a, b = random.sample(elite[:min(20, len(elite))], 2)
        child = _crossover_pair(a.perm, b.perm)
        hypotheses.append({
            "name": f"crossover_{i}",
            "description": f"OX1 crossover of {a.source} × {b.source}",
            "type": "permutation",
            "data": {"perm": child},
        })

    return hypotheses


# ---------------------------------------------------------------------------
# Bean-guided phases (run once, results persist)
# ---------------------------------------------------------------------------

def run_bean_phases(state: CampaignState, num_workers: int) -> None:
    """Run Bean-guided analysis phases. Each phase runs once and persists."""

    # --- Phase 1: Identity baseline + Bean diagnostic ---
    if not state.bean_baseline_done:
        print("\n" + "=" * 70)
        print("  BEAN PHASE 1: Identity Baseline + Diagnostic")
        print("  (Testing direct decryption — no transposition)")
        print("=" * 70 + "\n")

        start = time.monotonic()
        diag = run_identity_and_bean_diagnostic()
        elapsed = time.monotonic() - start

        print(f"  Tested {diag['total_combos']} keyword/cipher/alphabet combos in {elapsed:.1f}s\n")

        print("  Top 10 by quadgram score (identity permutation):")
        for i, r in enumerate(diag["top_by_score"][:10]):
            bean_str = f"Bean eq={r['bean_eq']} ineq={r['bean_ineq_pass']}/21"
            md_str = f"minor_diff={r['minor_diff_mean']:.1f}"
            print(f"    {i+1:2d}. {r['method']:<30s} score={r['score']:>8.1f}  "
                  f"cribs={r['crib_hits']:<3d} {bean_str}  {md_str}")

        if diag["top_by_score"]:
            state.bean_identity_top_score = diag["top_by_score"][0]["score"]

        # Save detailed diagnostic
        diag_path = CAMPAIGN_DIR / "bean_diagnostic.json"
        CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
        diag_path.write_text(json.dumps(diag, indent=2))
        print(f"\n  Diagnostic saved: {diag_path.name}")

        state.bean_baseline_done = True
        save_state(state)

    # --- Phase 2: Exhaustive single-swap search ---
    if not state.bean_single_swap_done:
        print("\n" + "=" * 70)
        print("  BEAN PHASE 2: Exhaustive Single-Swap Search")
        print("  (Testing all C(97,2)=4,656 CT swaps per keyword combo)")
        print("=" * 70 + "\n")

        start = time.monotonic()
        swap_result = run_exhaustive_single_swap(num_workers=num_workers)
        elapsed = time.monotonic() - start

        n_found = swap_result["improvements_found"]
        print(f"  Tested {swap_result['total_combos']} combos × "
              f"{swap_result['swaps_per_combo']} swaps in {elapsed:.1f}s")
        print(f"  Found {n_found} improving swaps\n")

        if swap_result["top_results"]:
            print("  Top 15 single swaps:")
            for i, r in enumerate(swap_result["top_results"][:15]):
                print(f"    {i+1:2d}. {r['method']:<50s} score={r['score']:>8.1f}  "
                      f"cribs={r['crib_hits']:<3d}  Δ={r['improvement']:+.1f}")

        if swap_result.get("hot_positions"):
            print("\n  Hot-swap positions (most frequently in top results):")
            for pos, freq in swap_result["hot_positions"][:15]:
                print(f"    Position {pos:2d} — appeared in {freq} top results")

        if swap_result["best"]:
            state.bean_best_swap_improvement = swap_result["best"]["improvement"]

        # Save hot swap pairs for Phase 3
        hot_pairs = [r["swap"] for r in swap_result["top_results"][:50]]
        state.bean_hot_swaps = hot_pairs

        # Add best results to elite
        for r in swap_result["top_results"][:20]:
            perm = list(range(K4_LEN))
            perm[r["swap"][0]], perm[r["swap"][1]] = perm[r["swap"][1]], perm[r["swap"][0]]
            member = EliteMember(
                perm=perm, score=r["score"], method=r["method"],
                plaintext=r["plaintext"], crib_hits=r["crib_hits"],
                source="bean_single_swap", round_found=0,
            )
            state.add_elite(member)

        swap_path = CAMPAIGN_DIR / "bean_single_swap.json"
        swap_path.write_text(json.dumps(swap_result, indent=2, default=str))
        print(f"\n  Results saved: {swap_path.name}")

        state.bean_single_swap_done = True
        save_state(state)

    # --- Phase 3: Focused double-swap search ---
    if not state.bean_double_swap_done and state.bean_hot_swaps:
        print("\n" + "=" * 70)
        print("  BEAN PHASE 3: Focused Double-Swap Search")
        print(f"  (Testing pairs from top {len(state.bean_hot_swaps)} single swaps)")
        print("=" * 70 + "\n")

        start = time.monotonic()
        dbl_result = run_focused_double_swap(
            hot_swap_pairs=state.bean_hot_swaps[:30],
            num_workers=num_workers,
        )
        elapsed = time.monotonic() - start

        print(f"  Tested C({dbl_result['pairs_tested']},2) swap combos in {elapsed:.1f}s")
        print(f"  Found {dbl_result['improvements_found']} double-swap improvements\n")

        if dbl_result["top_results"]:
            print("  Top 10 double swaps:")
            for i, r in enumerate(dbl_result["top_results"][:10]):
                print(f"    {i+1:2d}. {r['method']:<60s} score={r['score']:>8.1f}  "
                      f"cribs={r['crib_hits']:<3d}  Δ={r['improvement']:+.1f}")

            # Add best double-swap results to elite
            for r in dbl_result["top_results"][:10]:
                perm = list(range(K4_LEN))
                for swap in r["swaps"]:
                    perm[swap[0]], perm[swap[1]] = perm[swap[1]], perm[swap[0]]
                member = EliteMember(
                    perm=perm, score=r["score"], method=r["method"],
                    plaintext=r["plaintext"], crib_hits=r["crib_hits"],
                    source="bean_double_swap", round_found=0,
                )
                state.add_elite(member)

        dbl_path = CAMPAIGN_DIR / "bean_double_swap.json"
        dbl_path.write_text(json.dumps(dbl_result, indent=2, default=str))

        state.bean_double_swap_done = True
        save_state(state)

    # --- Phase 4: Near-identity hill-climbing ---
    if not state.bean_near_identity_done:
        print("\n" + "=" * 70)
        print("  BEAN PHASE 4: Near-Identity Hill-Climbing")
        print("  (Starting from identity, finding minimal swaps needed)")
        print("=" * 70 + "\n")

        start = time.monotonic()
        ni_result = run_near_identity_hillclimb(
            iterations=100000,
            num_workers=num_workers,
            top_n_combos=5,
        )
        elapsed = time.monotonic() - start

        if ni_result.get("score", -9999) > -9999:
            displaced = ni_result.get("displaced_positions", "?")
            print(f"  Best near-identity result:")
            print(f"    Score:     {ni_result['score']:.1f}")
            print(f"    Method:    {ni_result.get('method', '?')}")
            print(f"    Displaced: {displaced} positions from identity")
            print(f"    Cribs:     {ni_result.get('crib_hits', 0)}")
            print(f"    Bean eq:   {ni_result.get('bean_eq', '?')}")
            print(f"    Bean ineq: {ni_result.get('bean_ineq_pass', '?')}/21")
            print(f"    Time:      {elapsed:.1f}s")

            if ni_result.get("identity_top5"):
                print(f"\n  Identity screening top 5:")
                for s in ni_result["identity_top5"]:
                    print(f"    {s}")

            if ni_result.get("perm"):
                member = EliteMember(
                    perm=ni_result["perm"],
                    score=ni_result["score"],
                    method=ni_result.get("method", "near_identity"),
                    plaintext=ni_result.get("plaintext", ""),
                    crib_hits=ni_result.get("crib_hits", 0),
                    source="bean_near_identity",
                    round_found=0,
                )
                state.add_elite(member)
                state.update_best(
                    ni_result["score"], ni_result.get("crib_hits", 0),
                    ni_result.get("plaintext", ""), ni_result.get("method", ""),
                    ni_result["perm"],
                )

        ni_path = CAMPAIGN_DIR / "bean_near_identity.json"
        ni_path.write_text(json.dumps(ni_result, indent=2, default=str))

        state.bean_near_identity_done = True
        save_state(state)

    # --- Phase 5: Priority Keyword Deep Search ---
    if not state.priority_keyword_done:
        print("\n" + "=" * 70)
        print("  PHASE 5: Priority Keyword Deep Search")
        print("  Intensive hill-climbing with top Bean-plausibility keywords:")
        priority_kws = [kw for kw in dict.fromkeys(PRIORITY_KEYWORDS) if kw.isalpha()]
        for kw in priority_kws:
            print(f"    - {kw}")
        print(f"  (200K iterations × {num_workers}+ restarts per keyword/cipher/alphabet)")
        print("=" * 70 + "\n")

        start = time.monotonic()
        pk_result = run_priority_keyword_sweep(
            iterations=200000,
            num_workers=num_workers,
        )
        elapsed = time.monotonic() - start

        print(f"  Tested {pk_result['total_combos']} keyword/cipher/alphabet combos in {elapsed:.1f}s\n")

        # Per-keyword results
        print("  Per-keyword results:")
        print(f"  {'Keyword':15s} {'Score':>8s} {'Cribs':>6s} {'Disp':>5s} {'Method'}")
        print("  " + "-" * 65)
        for kw in priority_kws:
            if kw in pk_result.get("per_keyword", {}):
                r = pk_result["per_keyword"][kw]
                print(f"  {kw:15s} {r['best_score']:>8.1f} {r['best_crib_hits']:>6d} "
                      f"{r['displaced']:>5d} {r['best_method']}")

        # Overall best
        if pk_result.get("overall_best"):
            best = pk_result["overall_best"]
            print(f"\n  Overall best:")
            print(f"    Score:     {best['score']:.1f}")
            print(f"    Method:    {best['method']}")
            print(f"    Keyword:   {best.get('keyword', '?')}")
            print(f"    Cribs:     {best['crib_hits']}")
            print(f"    Displaced: {best.get('displaced_positions', '?')} positions")
            print(f"    PT:        {best['plaintext'][:60]}...")

            member = EliteMember(
                perm=best["perm"],
                score=best["score"],
                method=best["method"],
                plaintext=best["plaintext"],
                crib_hits=best["crib_hits"],
                source="priority_keyword",
                round_found=0,
            )
            state.add_elite(member)
            state.update_best(
                best["score"], best["crib_hits"],
                best["plaintext"], best["method"],
                best["perm"],
            )

        # Add top per-keyword results to elite
        for kw, r in pk_result.get("per_keyword", {}).items():
            if r.get("perm"):
                member = EliteMember(
                    perm=r["perm"],
                    score=r["best_score"],
                    method=r["best_method"],
                    plaintext=r.get("best_plaintext", ""),
                    crib_hits=r["best_crib_hits"],
                    source=f"priority_{kw}",
                    round_found=0,
                )
                state.add_elite(member)

        pk_path = CAMPAIGN_DIR / "priority_keyword_sweep.json"
        CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
        # Serialize without full perms for each result (too large)
        pk_save = {k: v for k, v in pk_result.items() if k != "top_results"}
        pk_save["top_results_summary"] = [
            {"score": r["score"], "method": r["method"], "crib_hits": r["crib_hits"],
             "plaintext": r["plaintext"][:50], "displaced": r.get("displaced_positions", -1)}
            for r in pk_result.get("top_results", [])[:30]
        ]
        pk_path.write_text(json.dumps(pk_save, indent=2, default=str))
        print(f"\n  Results saved: {pk_path.name}")

        state.priority_keyword_done = True
        state.priority_keyword_results = {
            kw: {"score": r["best_score"], "cribs": r["best_crib_hits"], "method": r["best_method"]}
            for kw, r in pk_result.get("per_keyword", {}).items()
        }
        save_state(state)


# ---------------------------------------------------------------------------
# Campaign loop
# ---------------------------------------------------------------------------

_shutdown_requested = False


def _signal_handler(signum, frame):
    global _shutdown_requested
    if not _shutdown_requested:
        _shutdown_requested = True
        print("\n  Shutdown requested — finishing current round and saving state...")


def run_campaign(
    *,
    budget: float = 250.0,
    model: str = "claude-sonnet-4-6",
    num_workers: int = 0,
    thinking_budget: int = 10000,
    local_only: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
    phase: str = "",
) -> None:
    """Main campaign loop. Runs until budget exhausted or Ctrl+C."""
    global _shutdown_requested

    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    state = load_state()
    state.budget_total = max(state.budget_total, budget)
    state.model = model

    if not state.started_at:
        state.started_at = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*70}")
    print(f"  KryptosBot Campaign — Bean-Guided + Priority Keyword Search")
    print(f"{'='*70}")
    print(f"  Budget:    ${state.budget_total:.2f} (${state.budget_spent:.2f} spent, ${state.budget_remaining:.2f} remaining)")
    print(f"  Rounds:    {state.rounds_completed} completed")
    print(f"  Elite:     {len(state.elite)} members")
    print(f"  Best ever: score={state.best_ever_score:.1f}, cribs={state.best_ever_crib_hits}")
    print(f"  Model:     {model}")
    print(f"  Workers:   {num_workers}")
    print(f"  Local:     {'YES' if local_only else 'no'}")
    print(f"  Bean:      baseline={'done' if state.bean_baseline_done else 'pending'} "
          f"swap={'done' if state.bean_single_swap_done else 'pending'} "
          f"double={'done' if state.bean_double_swap_done else 'pending'} "
          f"near_id={'done' if state.bean_near_identity_done else 'pending'}")
    print(f"  Priority:  {'done' if state.priority_keyword_done else 'PENDING'} "
          f"(DEFECTOR/PARALLAX/COLOPHON + {len(set(PRIORITY_KEYWORDS))-3} more)")
    if state.elite:
        print(f"  Top elite: {state.elite[0]['score']:.1f} ({state.elite[0]['method']})")
    print(f"{'='*70}\n")

    if dry_run:
        if state.elite:
            print("  Top 10 elite permutations:")
            for i, e in enumerate(state.elite[:10]):
                print(f"    {i+1}. score={e['score']:.1f} cribs={e['crib_hits']} "
                      f"method={e['method']} src={e['source']}")
            print(f"\n  Best plaintext: {state.best_ever_plaintext[:60]}...")
        return

    # --- Bean phases + priority keyword sweep (run once, free, no API) ---
    pending_phases = not all([
        state.bean_baseline_done,
        state.bean_single_swap_done,
        state.bean_double_swap_done,
        state.bean_near_identity_done,
        state.priority_keyword_done,
    ])
    if phase in ("bean", "keyword") or pending_phases:
        run_bean_phases(state, num_workers)
        if _shutdown_requested:
            _print_campaign_summary(state)
            return
        if phase in ("bean", "keyword"):
            _print_campaign_summary(state)
            return

    # --- Phase 0: Built-in reading orders (first run only) ---
    if state.rounds_completed == 0:
        print("\n--- Phase 0: Built-in reading orders (free) ---\n")
        builtin = [{
            "name": "reading_orders_all",
            "description": "All built-in grid reading orders",
            "type": "reading_orders_all",
            "data": {},
        }]
        results = test_all_hypotheses(builtin, num_workers=num_workers)
        _ingest_results(state, results, 0)
        _print_round_results(results)
        save_state(state)

    # --- API client ---
    client = None
    if not local_only:
        from kryptosbot.api_client import KryptosAPIClient

        api_key = _load_api_key()
        if not api_key:
            print("ERROR: No ANTHROPIC_API_KEY. Set in environment or kryptosbot/.env")
            print("  Falling back to local-only mode.")
            local_only = True
        else:
            client = KryptosAPIClient(
                api_key=api_key,
                model=model,
                budget_usd=state.budget_remaining,
                conversation_mode=True,
            )
            client._conversation_history = list(state.conversation_history)

    # --- Main loop ---
    round_num = state.rounds_completed
    try:
        while not _shutdown_requested:
            round_num += 1

            # Budget check
            if client and client.is_over_budget():
                print(f"\n  Budget exhausted (${state.budget_spent:.2f} / ${state.budget_total:.2f})")
                break

            remaining = state.budget_remaining - (client.usage.cost_usd if client else 0)
            if remaining <= 0:
                print(f"\n  Budget exhausted.")
                break

            print(f"\n{'='*70}")
            cost_str = f"${state.budget_spent + (client.usage.cost_usd if client else 0):.2f}/{state.budget_total:.2f}"
            print(f"  Round {round_num} — {cost_str} — elite={len(state.elite)}")
            print(f"{'='*70}\n")

            round_start = time.monotonic()
            round_results: list[HypothesisResult] = []

            # --- Decide what to do this round ---
            do_crossover = (round_num % CROSSOVER_INTERVAL == 0) and len(state.elite) >= 2
            do_depth = (round_num % DEPTH_INTERVAL == 0) and len(state.elite) >= 1
            do_opus = (round_num % OPUS_INSIGHT_INTERVAL == 0) and client and not local_only
            do_api = not local_only and client and not do_depth
            do_random = local_only and len(state.elite) < 10

            # --- Random seeds (bootstrap) ---
            if do_random:
                import random as _rng
                print("  [Bootstrap] Generating random permutation seeds...")
                random_hyps = []
                for ri in range(28):
                    perm = list(range(K4_LEN))
                    _rng.shuffle(perm)
                    random_hyps.append({
                        "name": f"random_seed_{round_num}_{ri}",
                        "description": "Random permutation seed for hill-climbing",
                        "type": "permutation",
                        "data": {"perm": perm},
                    })
                rnd_results = test_all_hypotheses(random_hyps, num_workers=num_workers)
                round_results.extend(rnd_results)
                _print_round_results(rnd_results, label="Random")

            # --- Crossover ---
            if do_crossover:
                print("  [Crossover] Generating offspring from elite...")
                elite_members = state.elite_members
                cx_hypotheses = generate_crossover_hypotheses(elite_members, count=20)
                cx_results = test_all_hypotheses(cx_hypotheses, num_workers=num_workers)
                round_results.extend(cx_results)
                _print_round_results(cx_results, label="Crossover")

            # --- API hypothesis generation (with Bean context) ---
            if do_api:
                print("  [Generate] Asking Claude for hypotheses...")
                context = _build_context(state, round_num)
                hypotheses = client.generate_hypotheses(
                    context, thinking_budget=thinking_budget,
                )

                if hypotheses:
                    print(f"  Generated {len(hypotheses)} hypotheses:")
                    for h in hypotheses:
                        print(f"    - {h.get('name', '?')} [{h.get('type', '?')}]")

                    for i, h in enumerate(hypotheses):
                        if (h.get("type") == "generator"
                                and not h.get("data", {}).get("python_code")
                                and not client.is_over_budget()):
                            print(f"  Generating script for: {h['name']}...")
                            code = client.generate_test_script(h, thinking_budget=thinking_budget)
                            if code:
                                hypotheses[i]["data"]["python_code"] = code

                    print(f"\n  Testing {len(hypotheses)} hypotheses...")
                    api_results = test_all_hypotheses(hypotheses, num_workers=num_workers)
                    round_results.extend(api_results)
                    _print_round_results(api_results, label="API")

            # --- Depth: multi-keyword hill-climb top elite ---
            if do_depth and state.elite:
                n_climb = min(5, len(state.elite))
                print(f"  [Depth] Multi-keyword hill-climb on top {n_climb} elite...")

                # Prioritize elite members from priority keyword sources
                priority_elite = [e for e in state.elite
                                  if any(kw.lower() in e.get('source', '').lower()
                                         or kw.lower() in e.get('method', '').lower()
                                         for kw in ['defector', 'parallax', 'colophon',
                                                    'horologe', 'priority'])]
                other_elite = [e for e in state.elite if e not in priority_elite]
                ordered_elite = (priority_elite + other_elite)[:n_climb]

                for i, e in enumerate(ordered_elite):
                    print(f"    Climbing elite #{i+1} (score={e['score']:.1f}, "
                          f"src={e.get('source', '?')})...")
                    hc = run_hillclimb_multi_keyword(
                        seed_perm=e["perm"],
                        iterations=HILLCLIMB_ITERS,
                        top_n_combos=MULTI_KW_TOP_N,
                        num_workers=num_workers,
                    )
                    hr = HypothesisResult(
                        name=f"depth_climb_{i}",
                        description=f"Multi-kw climb of elite #{i+1}",
                        candidates_tested=hc.get("total_restarts", 1),
                        best_score=hc["score"],
                        best_plaintext=hc.get("plaintext", ""),
                        best_method=hc.get("method", ""),
                        best_crib_hits=hc.get("crib_hits", 0),
                        elapsed_seconds=hc.get("elapsed_seconds", 0),
                        top_results=[hc],
                        best_perm=hc.get("perm"),
                    )
                    round_results.append(hr)
                    print(f"      score={hc['score']:.1f} method={hc.get('method', '?')} "
                          f"cribs={hc.get('crib_hits', 0)}")

            # --- Auto hill-climb promising results ---
            climbable = [r for r in round_results
                         if r.best_perm and r.best_score > HILLCLIMB_TRIGGER
                         and "hillclimb" not in r.name and "depth" not in r.name
                         and "mkhc" not in r.name]
            climbable.sort(key=lambda r: r.best_score, reverse=True)
            for r in climbable[:3]:
                if _shutdown_requested:
                    break
                print(f"  [Auto-climb] {r.name} (score={r.best_score:.1f})...")
                hc = run_hillclimb_multi_keyword(
                    seed_perm=r.best_perm,
                    iterations=HILLCLIMB_ITERS,
                    top_n_combos=MULTI_KW_TOP_N,
                    num_workers=num_workers,
                )
                hr = HypothesisResult(
                    name=f"{r.name}_mkhc",
                    description=f"Multi-kw hill-climb of {r.name}",
                    candidates_tested=hc.get("total_restarts", 1),
                    best_score=hc["score"],
                    best_plaintext=hc.get("plaintext", ""),
                    best_method=hc.get("method", ""),
                    best_crib_hits=hc.get("crib_hits", 0),
                    elapsed_seconds=hc.get("elapsed_seconds", 0),
                    top_results=[hc],
                    best_perm=hc.get("perm"),
                )
                round_results.append(hr)
                improvement = hc["score"] - r.best_score
                print(f"    score={hc['score']:.1f} (delta={improvement:+.1f})")

            # --- Ingest results ---
            _ingest_results(state, round_results, round_num)

            # --- API analysis ---
            if do_api and client and not client.is_over_budget() and round_results:
                print("\n  [Analyze] Sending results to Claude...")
                results_summary = [
                    {
                        "name": r.name,
                        "tested": r.candidates_tested,
                        "best_score": r.best_score,
                        "best_crib_hits": r.best_crib_hits,
                        "best_method": r.best_method,
                        "best_plaintext": r.best_plaintext[:40] + "..." if r.best_plaintext else "",
                    }
                    for r in round_results
                ]
                analysis = client.analyze_results(results_summary)
                print(f"    {analysis[:200]}...")

            # --- Opus deep analysis ---
            if do_opus and client:
                _run_opus_insight(state, client)

            # --- Update budget tracking ---
            if client:
                state.budget_spent += client.usage.cost_usd
                client.usage = type(client.usage)(model=client.model)
                client.budget_usd = state.budget_remaining
                state.conversation_history = list(client._conversation_history)
                if round_num % STALE_CONVERSATION_ROUNDS == 0:
                    client._conversation_history = client._conversation_history[-4:]
                    state.conversation_history = list(client._conversation_history)

            state.rounds_completed = round_num

            # --- Save state ---
            save_state(state)

            elapsed = time.monotonic() - round_start
            print(f"\n  Round {round_num} complete: {len(round_results)} results, "
                  f"{elapsed:.0f}s, elite={len(state.elite)}")

            # --- Breakthrough check ---
            for r in round_results:
                if r.best_crib_hits >= BREAKTHROUGH_CRIB_HITS and r.best_score > -400:
                    print(f"\n{'*'*70}")
                    print(f"  BREAKTHROUGH: {r.best_crib_hits} crib hits + score {r.best_score:.1f}!")
                    print(f"  Name: {r.name}")
                    print(f"  Method: {r.best_method}")
                    print(f"  PT: {r.best_plaintext}")
                    print(f"{'*'*70}")
                    _shutdown_requested = True
                    break

    except Exception as e:
        logger.error("Campaign error: %s", e, exc_info=True)
        print(f"\n  ERROR: {e}")
    finally:
        if client:
            state.budget_spent += client.usage.cost_usd
            state.conversation_history = list(client._conversation_history)
        state.rounds_completed = max(state.rounds_completed, round_num)
        save_state(state)
        _print_campaign_summary(state)


def _run_opus_insight(state: CampaignState, client) -> None:
    """Periodic Opus analysis for strategic pivots."""
    print("\n  [Opus Insight] Deep analysis...")

    original_model = client.model
    client.model = "claude-opus-4-6"

    elite_summary = "\n".join(
        f"  #{i+1}: score={e['score']:.1f} cribs={e['crib_hits']} "
        f"method={e['method']} src={e['source']}"
        for i, e in enumerate(state.elite[:20])
    )

    bean_status = (
        f"\nBean analysis status:\n"
        f"  Identity top score: {state.bean_identity_top_score:.1f}\n"
        f"  Best single-swap improvement: {state.bean_best_swap_improvement:.1f}\n"
        f"  Hot swap positions: {state.bean_hot_swaps[:10]}\n"
    )

    msg = f"""Campaign status after {state.rounds_completed} rounds:
- Budget: ${state.budget_spent:.2f} spent of ${state.budget_total:.2f}
- Elite population: {len(state.elite)} members
- Best ever: score={state.best_ever_score:.1f}, cribs={state.best_ever_crib_hits}
- Hypotheses tested: {state.total_hypotheses_tested}
- Candidates tested: {state.total_candidates_tested:,}
{bean_status}
Top 20 elite permutations:
{elite_summary}

Best plaintext so far: {state.best_ever_plaintext[:80]}

Priority keyword sweep results: {json.dumps(state.priority_keyword_results, indent=2) if state.priority_keyword_results else 'pending'}

Analyze the campaign with these focal hypotheses:
1. DEFECTOR as keyword: K4 may be about exfiltrating a defector from East Berlin.
   EASTNORTHEAST=compass bearing, BERLINCLOCK=checkpoint/timing signal.
   Berlin Wall fell Nov 1989; Kryptos dedicated Nov 1990. Does the plaintext support this?
2. PARALLAX and COLOPHON are known Sanborn keywords that pass Bean. Which scores highest?
3. Bean's statistics say most positions are one-to-one. Are our partial-swap results consistent?
4. What positions keep appearing in the elite methods? Are they structurally significant?
5. Are there untried approaches: autokey, Gromark, running key, Berlin Clock base-5?

Be specific and actionable."""

    msgs = [{"role": "user", "content": msg}]
    try:
        response = client._make_api_call(msgs, max_tokens=4096, thinking_budget=16000)
        if response:
            text = client._extract_text(response)
            insight_path = CAMPAIGN_DIR / f"opus_insight_round_{state.rounds_completed}.txt"
            insight_path.write_text(text)
            print(f"    Opus insight saved to {insight_path.name}")
            print(f"    {text[:300]}...")
    except Exception as e:
        logger.error("Opus insight failed: %s", e)

    client.model = original_model


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_api_key() -> str | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        return api_key
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip()
    return None


def _build_context(state: CampaignState, round_num: int) -> str:
    """Build context for API hypothesis generation — Bean-informed."""
    elite_lines = []
    for i, e in enumerate(state.elite[:15]):
        elite_lines.append(
            f"  #{i+1}: score={e['score']:.1f} cribs={e['crib_hits']} "
            f"method={e['method']} src={e['source']} [perm available]"
        )

    tried_count = len(state.tried_hashes)
    elite_str = "\n".join(elite_lines) if elite_lines else "  (none yet)"

    # Bean-specific context
    bean_context = ""
    if state.bean_baseline_done:
        bean_context += f"\nBean Analysis Results:\n"
        bean_context += f"  Identity (no transposition) best score: {state.bean_identity_top_score:.1f}\n"
    if state.bean_single_swap_done:
        bean_context += f"  Best single-swap improvement over identity: {state.bean_best_swap_improvement:.1f}\n"
    if state.bean_hot_swaps:
        flat_positions = {}
        for pair in state.bean_hot_swaps[:20]:
            for p in pair:
                flat_positions[p] = flat_positions.get(p, 0) + 1
        top_hot = sorted(flat_positions.items(), key=lambda x: x[1], reverse=True)[:10]
        bean_context += f"  Hot positions (most often in improving swaps): {top_hot}\n"

    return f"""Campaign round {round_num} ({state.rounds_completed} completed).
Budget: ${state.budget_spent:.2f} spent of ${state.budget_total:.2f}.
{bean_context}
Elite population ({len(state.elite)} members, top 15):
{elite_str}

Best ever: score={state.best_ever_score:.1f}, cribs={state.best_ever_crib_hits}
Unique permutations tested: {tried_count:,}

Generate NEW hypotheses exploring angles the elite hasn't covered.

KEY STRATEGY — PRIORITY KEYWORD FOCUS:
- Top Bean-plausibility keywords: DEFECTOR, PARALLAX, COLOPHON, HOROLOGE, PEDESTAL, MONOLITH
- DEFECTOR is the strongest narrative candidate: K4 may describe exfiltrating a
  defector from East Berlin (cribs EASTNORTHEAST=bearing, BERLINCLOCK=checkpoint/timing)
- Bean constraint at length 8 requires word[1]==word[3] (e.g. D-E-F-E-CTOR, P-A-R-A-LLAX)
- Bean's evidence says most CT↔PT positions are direct one-to-one substitution
- Focus on finding the FEW positions that might need transposing with these keywords
- Use "partial_swap" type for specific swap hypotheses
- Use "generator" type for systematic exploration of swap families
- Try non-periodic key models: autokey, Gromark at base 5/8/12/26, running key
- Consider if DIAWINFBN (positions 55-63, constant Δ4=5) marks a structural boundary

{f'This is round {round_num}, a depth round — crossover offspring also running. Focus on NOVEL approaches.' if round_num % CROSSOVER_INTERVAL == 0 else ''}"""


def _ingest_results(
    state: CampaignState,
    results: list[HypothesisResult],
    round_num: int,
) -> None:
    """Ingest round results into campaign state."""
    for r in results:
        state.total_hypotheses_tested += 1
        state.total_candidates_tested += r.candidates_tested

        state.update_best(
            r.best_score, r.best_crib_hits, r.best_plaintext,
            r.best_method, r.best_perm or [],
        )

        if r.best_perm and r.best_score > ELITE_ENTRY_SCORE:
            member = EliteMember(
                perm=r.best_perm,
                score=r.best_score,
                method=r.best_method,
                plaintext=r.best_plaintext,
                crib_hits=r.best_crib_hits,
                source=r.name,
                round_found=round_num,
            )
            added = state.add_elite(member)
            if added:
                logger.debug("Added to elite: %s (score=%.1f)", r.name, r.best_score)

        if r.best_perm:
            h = _perm_hash(r.best_perm)
            if h not in state.tried_hashes:
                state.tried_hashes.append(h)

    round_file = CAMPAIGN_DIR / f"round_{round_num:04d}.json"
    round_data = [
        {
            "name": r.name,
            "candidates_tested": r.candidates_tested,
            "best_score": r.best_score,
            "best_crib_hits": r.best_crib_hits,
            "best_method": r.best_method,
            "best_plaintext": r.best_plaintext[:50],
            "elapsed": r.elapsed_seconds,
        }
        for r in results
    ]
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    round_file.write_text(json.dumps(round_data, indent=2))


def _print_round_results(results: list[HypothesisResult], label: str = "") -> None:
    prefix = f"  [{label}] " if label else "  "
    for r in sorted(results, key=lambda x: x.best_score, reverse=True)[:10]:
        flag = " ***" if r.best_crib_hits >= 3 else ""
        print(f"{prefix}{r.name:<35} score={r.best_score:>8.1f}  "
              f"cribs={r.best_crib_hits:<3} tested={r.candidates_tested}{flag}")


def _print_campaign_summary(state: CampaignState) -> None:
    print(f"\n{'='*70}")
    print(f"  CAMPAIGN SUMMARY")
    print(f"{'='*70}")
    print(f"  Rounds completed:    {state.rounds_completed}")
    print(f"  Budget spent:        ${state.budget_spent:.2f} / ${state.budget_total:.2f}")
    print(f"  Hypotheses tested:   {state.total_hypotheses_tested}")
    print(f"  Candidates tested:   {state.total_candidates_tested:,}")
    print(f"  Elite population:    {len(state.elite)}")
    print(f"  Best score:          {state.best_ever_score:.1f}")
    print(f"  Best crib hits:      {state.best_ever_crib_hits}")
    print(f"  Best method:         {state.best_ever_method}")
    print(f"\n  Bean Analysis:")
    print(f"    Baseline:          {'done' if state.bean_baseline_done else 'pending'}")
    print(f"    Single-swap:       {'done' if state.bean_single_swap_done else 'pending'}")
    print(f"    Double-swap:       {'done' if state.bean_double_swap_done else 'pending'}")
    print(f"    Near-identity HC:  {'done' if state.bean_near_identity_done else 'pending'}")
    print(f"    Identity top:      {state.bean_identity_top_score:.1f}")
    print(f"    Best swap Δ:       {state.bean_best_swap_improvement:.1f}")
    print(f"\n  Priority Keyword Sweep:")
    print(f"    Status:            {'done' if state.priority_keyword_done else 'PENDING'}")
    if state.priority_keyword_results:
        for kw, r in sorted(state.priority_keyword_results.items(),
                            key=lambda x: x[1].get("score", -9999), reverse=True):
            print(f"    {kw:15s} score={r.get('score', -9999):.1f}  "
                  f"cribs={r.get('cribs', 0)}  {r.get('method', '')}")
    if state.best_ever_plaintext:
        print(f"\n  Best plaintext:      {state.best_ever_plaintext[:60]}...")
    if state.elite:
        print(f"\n  Top 5 elite:")
        for i, e in enumerate(state.elite[:5]):
            print(f"    {i+1}. score={e['score']:.1f} cribs={e['crib_hits']} "
                  f"method={e['method']} src={e['source']}")
    print(f"\n  State saved: {STATE_FILE}")
    print(f"  Resume with: PYTHONPATH=src python3 -u kryptosbot/campaign.py")
    print(f"{'='*70}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="campaign.py",
        description="KryptosBot Campaign — Bean-guided + evolutionary K4 search",
    )
    parser.add_argument("--budget", type=float, default=250.0,
                        help="Total API budget in USD (default: $250)")
    parser.add_argument("--model", type=str, default="claude-sonnet-4-6",
                        choices=["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"],
                        help="Model for hypothesis generation (default: sonnet)")
    parser.add_argument("--workers", type=int, default=0,
                        help="CPU workers (default: all cores)")
    parser.add_argument("--thinking", type=int, default=4096,
                        help="Extended thinking budget in tokens (default: 4096)")
    parser.add_argument("--local-only", action="store_true",
                        help="No API calls — hill-climb/crossover elite only (free)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show campaign state without running")
    parser.add_argument("--verbose", action="store_true",
                        help="Debug logging")
    parser.add_argument("--reset", action="store_true",
                        help="Reset campaign state (start fresh)")
    parser.add_argument("--phase", type=str, default="",
                        choices=["", "bean", "keyword"],
                        help="Run only a specific phase (bean = Bean phases, keyword = priority keyword sweep)")

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
        num_workers=args.workers,
        thinking_budget=args.thinking,
        local_only=args.local_only,
        dry_run=args.dry_run,
        verbose=args.verbose,
        phase=args.phase,
    )


if __name__ == "__main__":
    main()
