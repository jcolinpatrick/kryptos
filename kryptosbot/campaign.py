#!/usr/bin/env python3
"""
KryptosBot Campaign Runner — Two-system K4 solver.

Architecture (2026-03-09, updated after periodic-sub impossibility proof):
    Phase 1: Bean Baseline — identity decryption + Bean diagnostics (free)
    Phase 2: Exhaustive single-swap search (optional, low-value)
    Phase 3: Focused double-swap (optional, low-value)
    Phase 4: Near-identity hill-climbing (free)
    Phase 5: Priority keyword deep search (free)
    Phase 6: Null-mask SA search (free)
    Phase 7+: Evolutionary crossover + API-guided hypotheses (recurring)

PROVEN (2026-03-09): No periodic sub (Vig/Beau/VBeau × AZ/KA, periods 1-26)
is crib-consistent on the raw 97-char carved text. Two systems required.
Model A: remove nulls first → 73-char CT → decrypt. Model B: decrypt all 97 → read 73.
~1.66M null-mask configs tested so far: ZERO signal.

Usage:
    PYTHONPATH=src python3 -u kryptosbot/campaign.py
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --budget 50
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --local-only
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --dry-run
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --phase bean    # Bean phases only
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --phase null    # Null-mask SA only
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
    # Product cipher functions
    run_product_cipher_w9,
    run_product_cipher_general,
    run_running_key_product,
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
    # Null-mask SA state
    null_mask_done: bool = False
    null_mask_best_score: float = -9999.0
    null_mask_best_positions: list[int] = field(default_factory=list)
    # Product cipher phases (transposition × substitution)
    product_w9_done: bool = False
    product_w9_best_score: float = -9999.0
    product_w9_best_method: str = ""
    product_general_done: bool = False
    product_general_best_score: float = -9999.0
    running_key_done: bool = False
    running_key_best_score: float = -9999.0

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
        if len(a.perm) != len(b.perm):
            continue  # skip mismatched-length parents
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
            bean_str = f"Bean eq={r['bean_eq']} ineq={r['bean_ineq_pass']}/242"
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
            print(f"    Bean ineq: {ni_result.get('bean_ineq_pass', '?')}/242")
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

    # --- Phase 6: Null-mask SA search (73-char hypothesis) ---
    if not state.null_mask_done:
        print("\n" + "=" * 70)
        print("  PHASE 6: Null-Mask SA Search (73-char hypothesis)")
        print("  Finding which 24 of 97 K4 positions are nulls.")
        print("  Model: remove 24 nulls → 73-char CT → Vig/Beau decrypt → English")
        print("=" * 70 + "\n")

        start = time.monotonic()
        nm_result = _run_null_mask_sa(num_workers=num_workers)
        elapsed = time.monotonic() - start

        best = nm_result.get("best", {})
        print(f"  Null-mask SA completed in {elapsed:.1f}s")
        print(f"  Restarts:    {nm_result.get('restarts', 0)}")
        print(f"  Best score:  {best.get('score', -9999):.1f}")
        print(f"  Best method: {best.get('method', '?')}")
        print(f"  Null count:  {len(best.get('null_positions', []))}")
        if best.get('plaintext'):
            print(f"  Best PT:     {best['plaintext'][:60]}...")
        if best.get('crib_hits', 0) > 0:
            print(f"  CRIB HITS:   {best['crib_hits']} ***")

        state.null_mask_done = True
        state.null_mask_best_score = best.get("score", -9999.0)
        state.null_mask_best_positions = best.get("null_positions", [])

        if best.get("score", -9999) > ELITE_ENTRY_SCORE:
            # Build a permutation that represents the null removal
            # (identity perm of the 73 non-null positions)
            non_null = [i for i in range(K4_LEN) if i not in set(best.get("null_positions", []))]
            member = EliteMember(
                perm=non_null,  # Not a standard 97-perm; stored as position list
                score=best["score"],
                method=best.get("method", "null_mask_sa"),
                plaintext=best.get("plaintext", ""),
                crib_hits=best.get("crib_hits", 0),
                source="null_mask_sa",
                round_found=0,
            )
            state.add_elite(member)

        nm_path = CAMPAIGN_DIR / "null_mask_sa.json"
        CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
        nm_path.write_text(json.dumps(nm_result, indent=2, default=str))
        print(f"\n  Results saved: {nm_path.name}")
        save_state(state)

    # --- Phase 7: Product cipher — width 9 exhaustive ---
    if not state.product_w9_done:
        print("\n" + "=" * 70)
        print("  PHASE 7: Product Cipher — Width 9 Exhaustive")
        print("  Model: PT → columnar transposition (w=9) → periodic sub → CT")
        print("  Testing all 9!=362,880 column orders × Vig/Beau/VBeau × AZ/KA × p1-13")
        print("  + autokey with single-char primers")
        print("=" * 70 + "\n")

        start = time.monotonic()
        pw9_result = run_product_cipher_w9(num_workers=num_workers)
        elapsed = time.monotonic() - start

        best = pw9_result.get("best", {})
        print(f"  Product W9 completed in {elapsed:.1f}s")
        print(f"  Total perms: {pw9_result.get('total_perms', 0):,}")
        print(f"  Total configs: {pw9_result.get('total_configs', 0):,}")
        print(f"  Best score:  {best.get('score', -9999):.1f}")
        print(f"  Best method: {best.get('method', '?')}")
        if best.get('crib_hits', 0) > 0:
            print(f"  CRIB HITS:   {best['crib_hits']} ***")
        if best.get('plaintext'):
            print(f"  Best PT:     {best['plaintext'][:60]}...")

        if pw9_result.get("top_by_cribs"):
            print(f"\n  Top results by crib hits:")
            for i, r in enumerate(pw9_result["top_by_cribs"][:5]):
                print(f"    {i+1}. cribs={r['crib_hits']} score={r['score']:.1f} "
                      f"method={r['method'][:60]}")

        state.product_w9_done = True
        state.product_w9_best_score = best.get("score", -9999.0)
        state.product_w9_best_method = best.get("method", "")

        pw9_path = CAMPAIGN_DIR / "product_w9.json"
        CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
        pw9_path.write_text(json.dumps(pw9_result, indent=2, default=str))
        print(f"\n  Results saved: {pw9_path.name}")
        save_state(state)

    # --- Phase 8: Product cipher — general widths ---
    if not state.product_general_done:
        print("\n" + "=" * 70)
        print("  PHASE 8: Product Cipher — General Widths (4-14)")
        print("  Keyword-derived column orders × Vig/Beau/VBeau × AZ/KA × p1-13")
        print("=" * 70 + "\n")

        start = time.monotonic()
        pg_result = run_product_cipher_general(num_workers=num_workers)
        elapsed = time.monotonic() - start

        best = pg_result.get("best", {})
        print(f"  Product General completed in {elapsed:.1f}s")
        print(f"  Total configs: {pg_result.get('total_configs', 0):,}")
        print(f"  Best score:  {best.get('score', -9999):.1f}")
        print(f"  Best method: {best.get('method', '?')}")
        if best.get('crib_hits', 0) > 0:
            print(f"  CRIB HITS:   {best['crib_hits']} ***")
        if best.get('plaintext'):
            print(f"  Best PT:     {best['plaintext'][:60]}...")

        if pg_result.get("per_width"):
            print(f"\n  Per-width results:")
            for w in sorted(pg_result["per_width"].keys()):
                r = pg_result["per_width"][w]
                print(f"    Width {w:2d}: score={r['score']:.1f} cribs={r['crib_hits']} "
                      f"method={r['method'][:50]}")

        state.product_general_done = True
        state.product_general_best_score = best.get("score", -9999.0)

        pg_path = CAMPAIGN_DIR / "product_general.json"
        CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
        pg_path.write_text(json.dumps(pg_result, indent=2, default=str))
        print(f"\n  Results saved: {pg_path.name}")
        save_state(state)

    # --- Phase 9: Running-key product cipher ---
    if not state.running_key_done:
        print("\n" + "=" * 70)
        print("  PHASE 9: Running-Key Product Cipher")
        print("  Keyword-derived transpositions × running-key from corpus passages")
        print("=" * 70 + "\n")

        start = time.monotonic()
        rk_result = run_running_key_product(num_workers=num_workers)
        elapsed = time.monotonic() - start

        best = rk_result.get("best", {})
        print(f"  Running-key product completed in {elapsed:.1f}s")
        print(f"  Total configs: {rk_result.get('total_configs', 0):,}")
        print(f"  Passages used: {rk_result.get('passages_used', 0)}")
        print(f"  Best score:  {best.get('score', -9999):.1f}")
        print(f"  Best method: {best.get('method', '?')}")
        if best.get('crib_hits', 0) > 0:
            print(f"  CRIB HITS:   {best['crib_hits']} ***")
        if best.get('plaintext'):
            print(f"  Best PT:     {best['plaintext'][:60]}...")

        state.running_key_done = True
        state.running_key_best_score = best.get("score", -9999.0)

        rk_path = CAMPAIGN_DIR / "running_key_product.json"
        CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
        rk_path.write_text(json.dumps(rk_result, indent=2, default=str))
        print(f"\n  Results saved: {rk_path.name}")
        save_state(state)


# ---------------------------------------------------------------------------
# Null-mask SA search (Phase 6)
# ---------------------------------------------------------------------------

def _null_mask_sa_worker(args: tuple) -> dict:
    """Single SA restart for null-mask search. Runs in worker process."""
    import random as rng
    import signal as _signal

    # Ignore SIGINT/SIGTERM in workers — let main process handle shutdown
    _signal.signal(_signal.SIGINT, _signal.SIG_IGN)
    _signal.signal(_signal.SIGTERM, _signal.SIG_IGN)

    seed, iterations, w_constrained = args
    rng.seed(seed)

    K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
    TOP_KEYWORDS = ["KOMPASS", "KRYPTOS", "DEFECTOR", "COLOPHON", "KOLOPHON",
                    "PARALLAX", "KRYPTA", "KRYPTEIA", "KLEPSYDRA", "ABSCISSA"]
    W_POSITIONS = {20, 36, 48, 58, 74}

    # Crib positions that CANNOT be nulls
    crib_positions = set()
    for pos, text in CRIBS:
        for j in range(len(text)):
            crib_positions.add(pos + j)

    # Available positions for nulls (non-crib)
    available = [i for i in range(97) if i not in crib_positions]

    # Load quadgrams
    from pathlib import Path
    qg_path = Path(__file__).resolve().parent.parent.parent / "data" / "english_quadgrams.json"
    if not qg_path.exists():
        qg_path = Path("data/english_quadgrams.json")
    import json as _json
    with open(qg_path) as f:
        qg = _json.load(f)
    qg_floor = min(qg.values()) - 1.0

    # Intel jargon terms for bonus scoring (avoids rejecting acronym-heavy plaintext)
    _jargon_high = ["DEADDROP", "CLASSIFIED", "INTERCEPT", "DEFECTOR", "GCHQ",
                     "STASI", "ASSET", "AGENT", "COVERT", "SECRET", "BURIED",
                     "HIDDEN", "MARKER", "SIGNAL", "CIPHER"]
    _jargon_med = ["CIA", "KGB", "NSA", "FBI", "DCI", "DDR", "GRU", "BND",
                    "SIGINT", "HUMINT", "OPSEC", "INTEL", "LANGLEY", "MOSCOW",
                    "BERLIN", "KREMLIN", "KRYPTOS", "SANBORN", "LODESTONE"]
    _jargon_low = ["NEAR", "STOP", "KNOW", "FIVE", "CLOCK", "POINT", "PACES",
                    "NORTH", "SOUTH", "EAST", "WEST", "LOCATION", "EXACTLY"]

    def score_text(text):
        if len(text) < 4:
            return -999.0
        qg_score = sum(qg.get(text[i:i+4], qg_floor) for i in range(len(text) - 3))
        # Intel jargon bonus
        bonus = 0.0
        upper = text.upper()
        for t in _jargon_high:
            if t in upper:
                bonus += 15.0
        for t in _jargon_med:
            if t in upper:
                bonus += 10.0
        for t in _jargon_low:
            if t in upper:
                bonus += 5.0
        return qg_score + bonus

    def vig_decrypt(ct, key, alpha=AZ):
        result = []
        klen = len(key)
        for i, c in enumerate(ct):
            ci = alpha.index(c)
            ki = alpha.index(key[i % klen])
            result.append(alpha[(ci - ki) % 26])
        return "".join(result)

    def beau_decrypt(ct, key, alpha=AZ):
        result = []
        klen = len(key)
        for i, c in enumerate(ct):
            ci = alpha.index(c)
            ki = alpha.index(key[i % klen])
            result.append(alpha[(ki - ci) % 26])
        return "".join(result)

    def evaluate_mask(null_set):
        """Remove nulls, decrypt with top keywords, return best score."""
        # Build reduced CT
        reduced = []
        pos_map = {}
        j = 0
        for i in range(97):
            if i not in null_set:
                reduced.append(K4[i])
                pos_map[i] = j
                j += 1
        reduced_ct = "".join(reduced)
        if len(reduced_ct) != 73:
            return -9999.0, "", "", 0

        best_score = -9999.0
        best_pt = ""
        best_method = ""
        best_cribs = 0

        for kw in TOP_KEYWORDS:
            for cname, dfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                for aname, alpha in [("AZ", AZ), ("KA", KA)]:
                    pt = dfn(reduced_ct, kw, alpha)
                    sc = score_text(pt)

                    # Check cribs at compressed positions
                    hits = 0
                    for crib_start, crib_text in CRIBS:
                        if crib_start in pos_map:
                            cs = pos_map[crib_start]
                            for k, ch in enumerate(crib_text):
                                if cs + k < len(pt) and pt[cs + k] == ch:
                                    hits += 1

                    combined = sc + hits * 5.0  # Bonus for crib hits
                    if combined > best_score:
                        best_score = combined
                        best_pt = pt
                        best_method = f"null/{cname}/{kw}/{aname} cribs={hits}"
                        best_cribs = hits

        return best_score, best_pt, best_method, best_cribs

    # Initialize: random 24 null positions (or W-constrained)
    if w_constrained:
        fixed_nulls = W_POSITIONS & set(available)
        remaining_avail = [p for p in available if p not in fixed_nulls]
        needed = 24 - len(fixed_nulls)
        if needed > 0 and len(remaining_avail) >= needed:
            extra = set(rng.sample(remaining_avail, needed))
            null_set = fixed_nulls | extra
        else:
            null_set = set(rng.sample(available, 24))
    else:
        null_set = set(rng.sample(available, 24))

    non_null = [p for p in available if p not in null_set]
    null_list = list(null_set)

    current_score, current_pt, current_method, current_cribs = evaluate_mask(null_set)
    best_score = current_score
    best_pt = current_pt
    best_method = current_method
    best_nulls = sorted(null_set)
    best_cribs = current_cribs

    # SA parameters
    temp = 5.0
    cooling = 0.99997
    min_temp = 0.01

    for step in range(iterations):
        # Neighbor: swap one null with one non-null (both from available)
        ni = rng.randrange(len(null_list))
        nni = rng.randrange(len(non_null))

        old_null = null_list[ni]
        old_nonnull = non_null[nni]

        null_set.discard(old_null)
        null_set.add(old_nonnull)
        null_list[ni] = old_nonnull
        non_null[nni] = old_null

        new_score, new_pt, new_method, new_cribs = evaluate_mask(null_set)

        delta = new_score - current_score
        if delta > 0 or rng.random() < (2.718281828 ** (delta / max(temp, 0.001))):
            current_score = new_score
            current_pt = new_pt
            current_method = new_method
            current_cribs = new_cribs
            if new_score > best_score:
                best_score = new_score
                best_pt = new_pt
                best_method = new_method
                best_nulls = sorted(null_set)
                best_cribs = new_cribs
        else:
            # Revert
            null_set.discard(old_nonnull)
            null_set.add(old_null)
            null_list[ni] = old_null
            non_null[nni] = old_nonnull

        temp *= cooling
        if temp < min_temp:
            temp = min_temp

    return {
        "score": best_score,
        "plaintext": best_pt,
        "method": best_method,
        "null_positions": best_nulls,
        "crib_hits": best_cribs,
        "seed": seed,
    }


def _run_null_mask_sa(
    iterations: int = 100000,
    num_workers: int = 0,
) -> dict:
    """Run parallel SA restarts searching for the 24 null positions."""
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    # Run both W-constrained and unconstrained restarts
    restarts = num_workers * 2  # Half W-constrained, half free
    tasks = []
    for i in range(restarts):
        w_constrained = (i < restarts // 2)
        tasks.append((i * 1000 + int(time.time()) % 10000, iterations, w_constrained))

    print(f"  Launching {restarts} SA restarts ({restarts//2} W-constrained, "
          f"{restarts//2} free) across {num_workers} workers...")
    print(f"  {iterations:,} steps per restart, {len(PRIORITY_KEYWORDS)} keywords × 2 ciphers × 2 alphabets")
    print(f"  (Note: 1.66M null-mask configs already tested in standalone scripts — all negative)")

    results = []
    with mp.Pool(num_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(_null_mask_sa_worker, tasks)):
            results.append(result)
            best_so_far = max(results, key=lambda r: r["score"])
            print(f"    [{i+1}/{restarts}] score={best_so_far['score']:.1f} "
                  f"method={best_so_far['method']}")

    best = max(results, key=lambda r: r["score"])
    return {
        "best": best,
        "restarts": restarts,
        "iterations_per_restart": iterations,
        "all_results": sorted(
            [{"score": r["score"], "method": r["method"], "crib_hits": r["crib_hits"],
              "null_positions": r["null_positions"]}
             for r in results],
            key=lambda r: r["score"],
            reverse=True,
        )[:20],
    }


# ---------------------------------------------------------------------------
# Campaign loop
# ---------------------------------------------------------------------------

_shutdown_requested = False
_main_pid = None


def _signal_handler(signum, frame):
    global _shutdown_requested
    # Only print from the main process, not from multiprocessing workers
    if os.getpid() != _main_pid:
        return
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
    global _shutdown_requested, _main_pid

    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    _main_pid = os.getpid()
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    state = load_state()
    state.budget_total = max(state.budget_total, budget)
    state.model = model

    if not state.started_at:
        state.started_at = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*70}")
    print(f"  KryptosBot Campaign — 73-Char Null Hypothesis + Bean-Guided Search")
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
    print(f"  Null-mask: {'done (score=' + f'{state.null_mask_best_score:.1f})' if state.null_mask_done else 'PENDING'}")
    print(f"  Product:   W9={'done (score=' + f'{state.product_w9_best_score:.1f})' if state.product_w9_done else 'PENDING'} "
          f"General={'done' if state.product_general_done else 'PENDING'} "
          f"RunKey={'done' if state.running_key_done else 'PENDING'}")
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

    # --- Bean phases + priority keyword sweep + null-mask SA + product cipher (run once, free, no API) ---
    pending_phases = not all([
        state.bean_baseline_done,
        state.bean_single_swap_done,
        state.bean_double_swap_done,
        state.bean_near_identity_done,
        state.priority_keyword_done,
        state.null_mask_done,
        state.product_w9_done,
        state.product_general_done,
        state.running_key_done,
    ])
    if phase in ("bean", "keyword", "null", "product") or pending_phases:
        run_bean_phases(state, num_workers)
        if _shutdown_requested:
            _print_campaign_summary(state)
            return
        if phase in ("bean", "keyword", "null", "product"):
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
            print("  No ANTHROPIC_API_KEY found. Running local-only (crossover + hill-climb).")
            print("  Set key in environment or kryptosbot/.env for API-guided search.")
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
            # In local-only mode, always do crossover (no API work available)
            do_crossover = (
                (round_num % CROSSOVER_INTERVAL == 0) or local_only
            ) and len(state.elite) >= 2
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

CURRENT PARADIGM: 73-char null hypothesis
- Model: 73-char PT → sub(keyword) → 73-char CT → insert 24 nulls → 97 carved
- Core problem: which 24 positions are nulls?
- W positions [20,36,48,58,74] bracket cribs — strong null candidates
- Triple-24: (97-73), (cribs 13+11), (Weltzeituhr 24 facets)

KEY QUESTIONS:
1. Do null-mask SA results show any structural pattern in the null positions?
2. What rule could Sanborn have used to decide where to insert nulls?
3. d=13 anomaly: Beaufort k%13 collisions 3.55× expected — period 13 = len(EASTNORTHEAST).
   Has this been exploited with null removal?
4. HOROLOGE and ENIGMA are ELIMINATED (pigeonhole). KRYPTOS (5/6), DEFECTOR (4/6) survive.
5. "Not standard English, second level of cryptanalysis" — telegram with W-delimiters?
6. Are there untried null-selection rules: Weltzeituhr mapping, K1-K3 derived masks,
   maintenance timer positions (20, 24, 8)?

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

KEY PARADIGM — 73-CHAR NULL HYPOTHESIS:
- Model: 73-char PT → substitution → 73-char CT → insert 24 nulls → 97 carved
- THE CORE PROBLEM: which 24 of 97 positions are nulls?
- Crib positions (21-33, 63-73) CANNOT be nulls
- W positions [20,36,48,58,74] are strong null candidates (bracket cribs)
- Triple-24: (97-73), (13+11 cribs), (Weltzeituhr facets)
- Two Systems CONFIRMED by Sanborn: substitution + null insertion
- d=13 anomaly: Beaufort k%13 collisions 3.55× expected (strongest signal)

PRODUCTIVE APPROACHES:
- Use "generator" type for null-mask candidates: enumerate 24 null positions, remove them,
  decrypt 73-char CT with keywords, score with quadgrams
- Try structural null patterns: every Nth position, positions where cipher==tableau, etc.
- Test period-13 Beaufort with null removal
- Use "partial_swap" type for targeted position exchanges
- Consider autokey, running key on 73-char reduced texts

KEYWORDS (strongest survivors): KRYPTOS (5/6), DEFECTOR (4/6), COLOPHON (3/6), ABSCISSA (3/6)
ELIMINATED keywords: HOROLOGE, ENIGMA (pigeonhole analysis)

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
    print(f"\n  Null-Mask SA:")
    print(f"    Status:            {'done' if state.null_mask_done else 'PENDING'}")
    if state.null_mask_done:
        print(f"    Best score:        {state.null_mask_best_score:.1f}")
        if state.null_mask_best_positions:
            print(f"    Best null pos:     {state.null_mask_best_positions[:10]}{'...' if len(state.null_mask_best_positions) > 10 else ''}")
    print(f"\n  Product Cipher (transposition × substitution):")
    print(f"    W9 exhaustive:     {'done (score=' + f'{state.product_w9_best_score:.1f})' if state.product_w9_done else 'PENDING'}")
    if state.product_w9_done and state.product_w9_best_method:
        print(f"    W9 best method:    {state.product_w9_best_method}")
    print(f"    General (w4-14):   {'done (score=' + f'{state.product_general_best_score:.1f})' if state.product_general_done else 'PENDING'}")
    print(f"    Running-key:       {'done (score=' + f'{state.running_key_best_score:.1f})' if state.running_key_done else 'PENDING'}")
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
                        choices=["", "bean", "keyword", "null", "product"],
                        help="Run only a specific phase (bean = Bean phases, keyword = priority keyword sweep, null = null-mask SA, product = product cipher)")

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
