#!/usr/bin/env python3
"""
KryptosBot Campaign Runner — Two-system K4 solver.

Architecture (2026-03-11, post product-cipher elimination):
    Phases 1-9:  Computational (free, run once, all cores)
                 Bean diagnostics, swap search, null-mask SA, product cipher
    Phase 10+:   Opus-guided exploration (API budget, recurring)
                 Opus reasons about K4 structure → proposes hypotheses → tests locally

PROVEN: No periodic sub on raw 97. No product cipher (columnar trans × periodic sub).
No null mask + periodic sub (p=1-23). Two systems required.
Encryption order: PT → transposition → substitution → carved text.

Usage:
    PYTHONPATH=src python3 -u kryptosbot/campaign.py
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --budget 250
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --local-only
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --dry-run
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --phase product
    PYTHONPATH=src python3 -u kryptosbot/campaign.py --reset
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
ELITE_SIZE = 50                 # Top N permutations to keep
HILLCLIMB_ITERS = 50000        # Iterations per hill-climb restart
MULTI_KW_TOP_N = 3             # Hill-climb top N keyword combos per seed
BREAKTHROUGH_CRIB_HITS = 10    # Crib hits that trigger breakthrough alert
STALE_CONVERSATION_ROUNDS = 20 # Reset conversation to avoid stale context

# Score thresholds
ELITE_ENTRY_SCORE = -500.0     # Min score to enter elite population
HILLCLIMB_TRIGGER = -450.0     # Auto hill-climb results above this

# Keywords proven impossible — never test these
ELIMINATED_KEYWORDS = {"HOROLOGE", "HOROLOGY", "ENIGMA"}


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
    model: str = "claude-opus-4-6"
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
        # Normalize by length to prevent short-string false positives
        pt_len = len(plaintext) if plaintext else 97
        per_char = score / max(pt_len, 1)
        best_per_char = self.best_ever_score / max(len(self.best_ever_plaintext), 1) \
            if self.best_ever_plaintext else -9999.0
        if per_char > best_per_char:
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
# Hypothesis filtering (prevent wasted cycles)
# ---------------------------------------------------------------------------

def _filter_hypotheses(hypotheses: list[dict]) -> list[dict]:
    """Filter out hypotheses testing proven-impossible configurations."""
    valid = []
    for h in hypotheses:
        name = h.get("name", "unnamed")
        data = h.get("data", {})
        desc = h.get("description", "").upper()

        # Check for eliminated keywords in data or description
        keyword = data.get("keyword", "").upper()
        if keyword in ELIMINATED_KEYWORDS:
            print(f"    [FILTERED] {name}: keyword {keyword} is eliminated")
            continue

        # Check description for eliminated keywords
        skip = False
        for ek in ELIMINATED_KEYWORDS:
            if ek in desc and "ELIMINATED" not in desc and "NOT" not in desc:
                print(f"    [FILTERED] {name}: references eliminated keyword {ek}")
                skip = True
                break
        if skip:
            continue

        valid.append(h)

    if len(valid) < len(hypotheses):
        print(f"    Filtered {len(hypotheses) - len(valid)} invalid hypotheses")
    return valid


def _purge_elite(state: CampaignState) -> int:
    """Remove elite entries using eliminated keywords or nonsense methods."""
    original = len(state.elite)
    cleaned = []
    for e in state.elite:
        method = e.get("method", "").upper()
        # Skip entries with eliminated keywords
        skip = False
        for ek in ELIMINATED_KEYWORDS:
            if ek in method:
                skip = True
                break
        if skip:
            continue
        # Skip entries with absurdly long keywords (> 12 chars = nonsense)
        parts = method.split("/")
        if len(parts) >= 2:
            kw = parts[1] if len(parts) > 1 else ""
            if len(kw) > 12 and kw not in ("ALEXANDERPLATZ", "MENGENLEHREUHR",
                                             "TUTANKHAMUN", "WELTZEITUHR"):
                continue
        cleaned.append(e)
    state.elite = cleaned
    state._sort_elite()
    removed = original - len(cleaned)
    if removed:
        print(f"  Purged {removed} invalid elite entries (eliminated keywords, nonsense)")
    return removed


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
    model: str = "claude-opus-4-6",
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
    state.budget_total = budget
    state.model = model

    if not state.started_at:
        state.started_at = datetime.now(timezone.utc).isoformat()

    # Purge invalid elite entries on load
    _purge_elite(state)

    print(f"\n{'='*70}")
    print(f"  KryptosBot Campaign — Two-System K4 Solver")
    print(f"{'='*70}")
    print(f"  Model:     {model}")
    print(f"  Budget:    ${state.budget_spent:.2f} / ${state.budget_total:.2f} "
          f"(${state.budget_remaining:.2f} remaining)")
    print(f"  Rounds:    {state.rounds_completed}")
    print(f"  Elite:     {len(state.elite)} members")
    print(f"  Workers:   {num_workers}")
    print(f"  Thinking:  {thinking_budget} tokens")
    print(f"  Compute:   bean={'done' if state.bean_baseline_done else 'pending'} "
          f"null={'done' if state.null_mask_done else 'pending'} "
          f"product={'done' if state.product_w9_done else 'pending'}")
    if state.elite:
        print(f"  Top elite: {state.elite[0]['score']:.1f} ({state.elite[0]['method']})")
    print(f"{'='*70}\n")

    if dry_run:
        _print_campaign_summary(state)
        return

    # --- Computational phases 1-9 (run once, free, no API) ---
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

    # --- API client setup ---
    client = None
    if not local_only:
        from kryptosbot.api_client import KryptosAPIClient

        api_key = _load_api_key()
        if not api_key:
            print("  No ANTHROPIC_API_KEY found.")
            print("  Set key in environment or kryptosbot/.env for Opus-guided search.")
            print("  All computational phases are complete.")
            _print_campaign_summary(state)
            return
        client = KryptosAPIClient(
            api_key=api_key,
            model=model,
            budget_usd=state.budget_remaining,
            conversation_mode=True,
        )
        client._conversation_history = list(state.conversation_history)
    else:
        print("  All computational phases complete. Use API mode for Opus-guided exploration.")
        _print_campaign_summary(state)
        return

    # --- Phase 10+: Opus-guided exploration ---
    print(f"\n  Entering Opus-guided exploration (budget: ${state.budget_remaining:.2f})")

    round_num = state.rounds_completed
    try:
        while not _shutdown_requested:
            round_num += 1

            # Budget check
            remaining = state.budget_remaining - client.usage.cost_usd
            if remaining <= 0 or client.is_over_budget():
                print(f"\n  Budget exhausted (${state.budget_spent:.2f} / ${state.budget_total:.2f})")
                break

            cost = state.budget_spent + client.usage.cost_usd
            print(f"\n{'='*70}")
            print(f"  Round {round_num} — ${cost:.2f}/${state.budget_total:.2f} — "
                  f"elite={len(state.elite)}")
            print(f"{'='*70}")

            round_start = time.monotonic()

            # --- Step 1: Build context for Opus ---
            context = _build_context(state, round_num)

            # --- Step 2: Ask Opus for hypotheses ---
            print(f"\n  [Opus] Generating hypotheses (thinking={thinking_budget})...")
            hypotheses = client.generate_hypotheses(
                context, thinking_budget=thinking_budget,
            )

            if not hypotheses:
                print("    No hypotheses generated. Retrying in 30s...")
                state.rounds_completed = round_num
                save_state(state)
                time.sleep(30)
                continue

            # --- Step 3: Filter invalid hypotheses ---
            hypotheses = _filter_hypotheses(hypotheses)

            print(f"  {len(hypotheses)} valid hypotheses:")
            for h in hypotheses:
                print(f"    - {h.get('name', '?')} [{h.get('type', '?')}] "
                      f"{h.get('description', '')[:70]}")

            # --- Step 4: For generator hypotheses, ask Opus to write code ---
            for i, h in enumerate(hypotheses):
                if (h.get("type") == "generator"
                        and not h.get("data", {}).get("python_code")
                        and not client.is_over_budget()):
                    print(f"\n  [Opus] Writing test script: {h['name']}...")
                    code = client.generate_test_script(h, thinking_budget=thinking_budget)
                    if code:
                        hypotheses[i]["data"]["python_code"] = code
                        print(f"    Generated {len(code)} chars of code")

            # --- Step 4b: Persist hypothesis code ---
            code_dir = CAMPAIGN_DIR / "hypothesis_code"
            code_dir.mkdir(parents=True, exist_ok=True)
            for h in hypotheses:
                code = h.get("data", {}).get("python_code", "")
                if code:
                    code_file = code_dir / f"round_{round_num:04d}_{h.get('name', 'unknown')}.py"
                    code_file.write_text(
                        f"# Hypothesis: {h.get('name', '?')}\n"
                        f"# Round: {round_num}\n"
                        f"# Description: {h.get('description', '')[:200]}\n"
                        f"# Type: {h.get('type', '?')}\n\n"
                        f"{code}\n"
                    )

            # --- Step 5: Test hypotheses locally ---
            round_results: list[HypothesisResult] = []
            if hypotheses:
                print(f"\n  [Test] Executing {len(hypotheses)} hypotheses "
                      f"({num_workers} workers)...")
                round_results = test_all_hypotheses(
                    hypotheses, num_workers=num_workers,
                )
                _print_round_results(round_results)

                # Auto hill-climb any promising results
                climbable = [r for r in round_results
                             if r.best_perm and r.best_score > HILLCLIMB_TRIGGER
                             and "hillclimb" not in r.name
                             and "hc" not in r.name]
                climbable.sort(key=lambda r: r.best_score, reverse=True)
                for r in climbable[:2]:
                    if _shutdown_requested:
                        break
                    print(f"  [Hill-climb] {r.name} (score={r.best_score:.1f})...")
                    hc = run_hillclimb_multi_keyword(
                        seed_perm=r.best_perm,
                        iterations=HILLCLIMB_ITERS,
                        top_n_combos=MULTI_KW_TOP_N,
                        num_workers=num_workers,
                    )
                    hr = HypothesisResult(
                        name=f"{r.name}_hc",
                        description=f"Hill-climb of {r.name}",
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
                    delta = hc["score"] - r.best_score
                    print(f"    score={hc['score']:.1f} (Δ={delta:+.1f})")

                # Ingest results
                _ingest_results(state, round_results, round_num)

            # --- Step 6: Feed results back to Opus ---
            if round_results and not client.is_over_budget():
                results_summary = [
                    {
                        "name": r.name,
                        "tested": r.candidates_tested,
                        "best_score": r.best_score,
                        "best_score_per_char": round(r.best_score / max(len(r.best_plaintext), 1), 2)
                            if r.best_plaintext else 0.0,
                        "pt_length": len(r.best_plaintext) if r.best_plaintext else 0,
                        "best_crib_hits": r.best_crib_hits,
                        "best_method": r.best_method,
                        "best_plaintext": r.best_plaintext[:50] + "..."
                            if r.best_plaintext else "",
                    }
                    for r in round_results
                ]
                print(f"\n  [Opus] Analyzing results...")
                analysis = client.analyze_results(results_summary)
                if analysis:
                    print(f"    {analysis[:300]}...")

            # --- Update state ---
            state.budget_spent += client.usage.cost_usd
            client.usage = type(client.usage)(model=client.model)
            client.budget_usd = state.budget_remaining
            state.conversation_history = list(client._conversation_history)

            if round_num % STALE_CONVERSATION_ROUNDS == 0:
                client._conversation_history = client._conversation_history[-4:]
                state.conversation_history = list(client._conversation_history)

            state.rounds_completed = round_num
            save_state(state)

            elapsed = time.monotonic() - round_start
            print(f"\n  Round {round_num} complete: {len(round_results)} results, "
                  f"{elapsed:.0f}s")

            # --- Breakthrough check ---
            for r in round_results:
                if r.best_crib_hits >= BREAKTHROUGH_CRIB_HITS and r.best_score > -400:
                    print(f"\n{'*'*70}")
                    print(f"  BREAKTHROUGH: {r.best_crib_hits} crib hits!")
                    print(f"  Score:  {r.best_score:.1f}")
                    print(f"  Method: {r.best_method}")
                    print(f"  PT:     {r.best_plaintext}")
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


    # _run_opus_insight removed — Opus is now the primary model for all rounds


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
    """Build rich context for Opus hypothesis generation."""
    elite_lines = []
    for i, e in enumerate(state.elite[:10]):
        pt = e.get('plaintext', '')
        pt_len = len(pt) if pt else 97
        per_char = e['score'] / max(pt_len, 1)
        elite_lines.append(
            f"  #{i+1}: score={e['score']:.1f} ({per_char:.2f}/char, {pt_len} chars) "
            f"cribs={e['crib_hits']} method={e['method']}"
        )
    elite_str = "\n".join(elite_lines) if elite_lines else "  (none)"

    # Summarize what computational phases found
    compute_summary = []
    if state.product_w9_done:
        compute_summary.append(
            f"Product W9 (362K perms × sub): best={state.product_w9_best_score:.1f} — NO SIGNAL")
    if state.product_general_done:
        compute_summary.append(
            f"Product General (w4-14 × keywords): best={state.product_general_best_score:.1f} — NO SIGNAL")
    if state.running_key_done:
        compute_summary.append(
            f"Running-key product: best={state.running_key_best_score:.1f} — NO SIGNAL")
    if state.null_mask_done:
        compute_summary.append(
            f"Null-mask SA: best={state.null_mask_best_score:.1f} — NO SIGNAL")
    compute_str = "\n".join(f"  - {s}" for s in compute_summary) if compute_summary else "  (pending)"

    return f"""Round {round_num} of Opus-guided K4 exploration.
Budget: ${state.budget_spent:.2f} / ${state.budget_total:.2f}.
Hypotheses tested: {state.total_hypotheses_tested:,}. Candidates: {state.total_candidates_tested:,}.

COMPUTATIONAL PHASE RESULTS (all ZERO signal):
{compute_str}

Top elite ({len(state.elite)} members):
{elite_str}

SCORING GUIDE (CRITICAL — avoid false positives):
- Quadgram score is LENGTH-DEPENDENT: shorter plaintext = smaller absolute score.
  ALWAYS compare per-char scores: English ≈ -2.5/char, random ≈ -4.5/char.
  A -294 score on 48 chars = -6.1/char (NOISE), NOT better than -580 on 97 chars (-6.0/char).
- Crib hits: ONLY meaningful when plaintext is exactly 97 chars (matching CT positions).
  If your generator outputs <97 chars, crib positions are WRONG — hits are coincidental.
- SIGNAL requires: ≥10 crib hits AND score/char > -4.0 AND plaintext length = 97.
- PERIOD-13 TRAP: Any period-13 cipher that derives its key from EASTNORTHEAST (pos 21-33)
  gets 13/13 ENE hits FOR FREE — those 13 positions cover all 13 residues mod 13, so the
  base key is fully determined. Only BERLINCLOCK hits (pos 63-73) are independent tests.
  The null distribution shows max 3/11 BC hits at p=55% — NOT significant. Do NOT propose
  period-13 progressive key, period-13 Beaufort, or similar unless BC hits alone exceed 5.

WHAT THIS MEANS: Standard approaches are exhausted. The method is NOT:
- Periodic substitution (any period, any variant) on the raw 97 chars
- Standard columnar transposition followed by periodic substitution
- Running key from Howard Carter's book or K1-K3 plaintext
- Null removal + periodic substitution (any period 1-23)
- Progressive key period-13 (any step, any variant, AZ/KA): 13 ENE hits are FREE, max 3/11 BC = noise (p=55%)

IMPORTANT: The old "generator" type only returns PERMUTATIONS, then the framework
applies periodic substitution — which is proven impossible. This caused all your
recent hypotheses to crash (tested: 0). USE "plaintext_generator" INSTEAD.
The "plaintext_generator" type lets you do your OWN transposition + substitution
in the generate() function and return plaintext candidates directly.

THE METHOD MUST BE something we haven't tried yet. Think creatively:

OPEN HYPOTHESES (highest priority):
1. Non-columnar transposition + non-periodic substitution (autokey, Quagmire,
   custom tableau). Use "plaintext_generator" — implement both layers yourself.
2. The d=13 anomaly: Beaufort keystream mod 13 has 7.09× expected collisions.
   Period-13 progressive key is ELIMINATED (p=55%, noise). The anomaly may hint at
   a period-13 component WITHIN a more complex scheme (e.g., after transposition).
3. Grille-based null selection: 24 of 97 positions are nulls, removed before
   decryption. The rule for which 24 is unknown. 5 W's bracket the cribs.
4. Double transposition: two transposition layers before substitution.
5. K3-inspired: K3 uses double rotational transposition (24×14 → 8×42).
   A VARIANT of this method (different grid dimensions) hasn't been tested.
6. Width-13 × 8 rows matches "8 lines" from Sanborn's legal pad.
   Width-14 has both cribs starting at the same column.
7. Bespoke but hand-executable — Scheidt/Sanborn designed something elegant
   that combines familiar components in a novel way.

CONSTRAINTS:
- Keywords HOROLOGE and ENIGMA are ELIMINATED (do not use)
- Top keyword survivors: KRYPTOS, KOMPASS, DEFECTOR, COLOPHON, ABSCISSA
- Encryption order proven: PT → transposition → substitution → CT
- Bean stats suggest the substitution alphabet is near-standard (keyword-based)
- PT is "not standard English, second level of cryptanalysis needed"
- Keep code SIMPLE: under 50 lines per generator, filter with crib_hits() >= 2

Generate hypotheses using "plaintext_generator" type.
Write simple, clean Python that implements your full cipher hypothesis."""


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
            "best_score_per_char": round(r.best_score / max(len(r.best_plaintext), 1), 2)
                if r.best_plaintext else 0.0,
            "best_pt_length": len(r.best_plaintext) if r.best_plaintext else 0,
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
        pt_len = len(r.best_plaintext) if r.best_plaintext else 0
        per_char = r.best_score / max(pt_len, 1) if pt_len else 0.0
        len_warn = f" [!{pt_len}ch]" if pt_len and pt_len != 97 else ""
        print(f"{prefix}{r.name:<35} score={r.best_score:>8.1f} ({per_char:.1f}/ch)  "
              f"cribs={r.best_crib_hits:<3} tested={r.candidates_tested}{len_warn}{flag}")


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
        description="KryptosBot Campaign — Opus-guided two-system K4 solver",
    )
    parser.add_argument("--budget", type=float, default=250.0,
                        help="Total API budget in USD (default: $250)")
    parser.add_argument("--model", type=str, default="claude-opus-4-6",
                        choices=["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"],
                        help="Model for hypothesis generation (default: opus)")
    parser.add_argument("--workers", type=int, default=0,
                        help="CPU workers (default: all cores)")
    parser.add_argument("--thinking", type=int, default=10000,
                        help="Extended thinking budget in tokens (default: 10000)")
    parser.add_argument("--local-only", action="store_true",
                        help="No API calls — computational phases only (free)")
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
