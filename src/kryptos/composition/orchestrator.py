"""Composition search orchestrator.

Enumerates candidate compositions from a policy, applies constraint
pruning, dispatches to scorers, and records results to the ledger.

Supports both serial and parallel execution via multiprocessing.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from kryptos.composition.models import (
    BranchStatus,
    CompositionResult,
    CompositionStack,
    LayerFamily,
    LayerInstance,
    PeelOrder,
    PruneResult,
)
from kryptos.composition.registry import (
    build_transforms,
    generate_params,
    get_layer_def,
    make_instance,
    registered_families,
)
from kryptos.composition.constraints import (
    evaluate_pruning,
    evaluate_intermediate_pruning,
)
from kryptos.composition.scoring_bridge import score_composition
from kryptos.composition.ledger import CompositionLedger
from kryptos.kernel.constants import CT, CT_LEN, STORE_THRESHOLD
from kryptos.kernel.persistence.artifacts import JsonlWriter


# ── Campaign policy ────────────────────────────────────────────────────

@dataclass
class CampaignPolicy:
    """Controls what a composition campaign searches and how.

    Restricts the combinatorial space and sets execution parameters.
    """
    name: str = "default"
    description: str = ""

    # Layer restrictions
    outer_families: List[str] = field(default_factory=lambda: ["additive_mask"])
    inner_families: List[str] = field(default_factory=lambda: ["identity"])

    # Peel orders to test
    peel_orders: List[str] = field(default_factory=lambda: ["outer_first"])

    # Parameter generation overrides
    outer_params: Dict[str, Any] = field(default_factory=dict)
    inner_params: Dict[str, Any] = field(default_factory=dict)

    # Pruning
    aggressive_pruning: bool = False
    score_threshold: int = STORE_THRESHOLD

    # Execution
    workers: int = 1
    beam_width: int = 0  # 0 = no beam limit
    ciphertext: str = CT

    # Persistence
    db_path: str = "db/composition_ledger.sqlite"
    log_dir: str = "artifacts/composition"

    # Resume
    force: bool = False  # If True, ignore checkpoints

    @property
    def campaign_id(self) -> str:
        payload = json.dumps(
            {
                "name": self.name,
                "outer": sorted(self.outer_families),
                "inner": sorted(self.inner_families),
                "peel": sorted(self.peel_orders),
                "outer_params": self.outer_params,
                "inner_params": self.inner_params,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "outer_families": self.outer_families,
            "inner_families": self.inner_families,
            "peel_orders": self.peel_orders,
            "outer_params": self.outer_params,
            "inner_params": self.inner_params,
            "aggressive_pruning": self.aggressive_pruning,
            "score_threshold": self.score_threshold,
            "workers": self.workers,
            "beam_width": self.beam_width,
            "db_path": self.db_path,
            "log_dir": self.log_dir,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CampaignPolicy":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ── Work item for parallel dispatch ────────────────────────────────────

def _make_branch_id(stack: CompositionStack) -> str:
    return stack.stack_hash


def _worker_evaluate(work_item: Dict[str, Any]) -> Dict[str, Any]:
    """Worker function for multiprocessing Pool.

    Evaluates a single composition branch: peel outer, score result.
    Must be a top-level function for pickling.
    """
    stack_dict = work_item["stack"]
    ct = work_item["ciphertext"]
    aggressive = work_item.get("aggressive_pruning", False)
    threshold = work_item.get("score_threshold", STORE_THRESHOLD)

    # Reconstruct stack
    stack = CompositionStack.from_dict(stack_dict)

    # Build transforms for each layer
    try:
        layer_transforms = []
        for layer in stack.layers:
            fwd, inv = build_transforms(layer)
            layer_transforms.append((fwd, inv))
    except Exception as e:
        return {
            "branch_id": work_item["branch_id"],
            "error": str(e),
            "score": 0,
        }

    # Apply decryption: peel layers in order
    text = ct
    intermediates: list[str] = []

    if stack.peel_order == PeelOrder.OUTER_FIRST:
        # Peel from outer (index 0) to inner (index -1)
        for i, (fwd, inv) in enumerate(layer_transforms):
            text = inv(text)
            if i < len(layer_transforms) - 1:
                intermediates.append(text)

                # Runtime pruning on intermediate
                prune = evaluate_intermediate_pruning(text, stack, aggressive)
                if prune.pruned:
                    return {
                        "branch_id": work_item["branch_id"],
                        "pruned": True,
                        "prune_type": prune.prune_type.value,
                        "prune_reason": prune.reason,
                        "score": 0,
                    }
    else:
        # INNER_FIRST: peel from inner to outer
        for i in range(len(layer_transforms) - 1, -1, -1):
            fwd, inv = layer_transforms[i]
            text = inv(text)
            if i > 0:
                intermediates.append(text)

                prune = evaluate_intermediate_pruning(text, stack, aggressive)
                if prune.pruned:
                    return {
                        "branch_id": work_item["branch_id"],
                        "pruned": True,
                        "prune_type": prune.prune_type.value,
                        "prune_reason": prune.reason,
                        "score": 0,
                    }

    plaintext = text
    intermediate = intermediates[0] if intermediates else ""

    # Score through canonical bridge
    result = score_composition(plaintext, stack, intermediate_text=intermediate)

    return {
        "branch_id": work_item["branch_id"],
        "score": result.crib_score,
        "bean_pass": result.bean_pass,
        "ic_value": result.ic_value,
        "ngram_score": result.ngram_score,
        "plaintext": plaintext if result.crib_score >= threshold else "",
        "intermediate_text": intermediate if result.crib_score >= threshold else "",
        "score_breakdown": result.score_breakdown,
        "pruned": False,
    }


# ── Orchestrator ───────────────────────────────────────────────────────

class CompositionOrchestrator:
    """Orchestrates composition campaign execution.

    Lifecycle:
    1. Enumerate compositions from policy
    2. Apply static pruning
    3. Dispatch surviving branches to workers
    4. Record results to ledger
    5. Report summary
    """

    def __init__(self, policy: CampaignPolicy) -> None:
        self.policy = policy
        self._interrupted = False

    def enumerate_stacks(self) -> List[CompositionStack]:
        """Generate all composition stacks from the policy."""
        stacks: list[CompositionStack] = []
        ct_len = len(self.policy.ciphertext)

        for outer_fam_name in self.policy.outer_families:
            outer_fam = LayerFamily(outer_fam_name)
            gen_kwargs = dict(self.policy.outer_params)
            # Inject length for transposition families on non-standard CT
            if ct_len != CT_LEN and not outer_fam.value.startswith(("identity", "additive", "vigenere", "beaufort", "var_beaufort")):
                gen_kwargs.setdefault("length", ct_len)
            outer_params_list = generate_params(outer_fam, **gen_kwargs)

            for inner_fam_name in self.policy.inner_families:
                inner_fam = LayerFamily(inner_fam_name)
                inner_gen_kwargs = dict(self.policy.inner_params)
                if ct_len != CT_LEN and not inner_fam.value.startswith(("identity", "additive", "vigenere", "beaufort", "var_beaufort")):
                    inner_gen_kwargs.setdefault("length", ct_len)
                inner_params_list = generate_params(inner_fam, **inner_gen_kwargs)

                for outer_params in outer_params_list:
                    # Inject length into instance params for transform factory
                    if ct_len != CT_LEN:
                        outer_params = {**outer_params, "length": ct_len}
                    outer_inst = make_instance(outer_fam, outer_params)

                    for inner_params in inner_params_list:
                        if ct_len != CT_LEN:
                            inner_params = {**inner_params, "length": ct_len}
                        inner_inst = make_instance(inner_fam, inner_params)

                        for peel_name in self.policy.peel_orders:
                            peel = PeelOrder(peel_name)
                            stack = CompositionStack(
                                layers=(outer_inst, inner_inst),
                                peel_order=peel,
                                description=(
                                    f"{outer_inst.display_label} -> "
                                    f"{inner_inst.display_label} "
                                    f"({peel.value})"
                                ),
                            )
                            stacks.append(stack)

        return stacks

    def run(self) -> Dict[str, Any]:
        """Execute the campaign. Returns summary statistics."""
        policy = self.policy

        # Enumerate
        print(f"[composition] Enumerating compositions for campaign '{policy.name}'...")
        all_stacks = self.enumerate_stacks()
        print(f"[composition] Generated {len(all_stacks)} candidate compositions")

        # Open ledger
        ledger = CompositionLedger(policy.db_path)
        ledger.register_campaign(
            campaign_id=policy.campaign_id,
            name=policy.name,
            policy=policy.to_dict(),
            total_branches=len(all_stacks),
        )

        # Check for resume
        completed = set()
        if not policy.force:
            completed = ledger.completed_branch_ids(policy.campaign_id)
            if completed:
                print(f"[composition] Resuming: {len(completed)} branches already done")

        # Static pruning
        work_items: list[Dict[str, Any]] = []
        pruned_count = 0
        skipped_count = 0

        for stack in all_stacks:
            branch_id = _make_branch_id(stack)

            if branch_id in completed:
                skipped_count += 1
                continue

            # Static pruning
            prune = evaluate_pruning(stack, aggressive=policy.aggressive_pruning,
                                     ct_length=len(policy.ciphertext))
            if prune.pruned:
                pruned_count += 1
                ledger.record_branch(
                    branch_id=branch_id,
                    campaign_id=policy.campaign_id,
                    stack_hash=stack.stack_hash,
                    stack_json=json.dumps(stack.to_dict()),
                    campaign_key=stack.campaign_key,
                    peel_order=stack.peel_order.value,
                    status="pruned",
                    prune_type=prune.prune_type.value,
                    prune_reason=prune.reason,
                )
                continue

            work_items.append({
                "branch_id": branch_id,
                "stack": stack.to_dict(),
                "ciphertext": policy.ciphertext,
                "aggressive_pruning": policy.aggressive_pruning,
                "score_threshold": policy.score_threshold,
            })

        # Apply beam width
        if policy.beam_width > 0 and len(work_items) > policy.beam_width:
            print(f"[composition] Beam limiting: {len(work_items)} -> {policy.beam_width}")
            work_items = work_items[:policy.beam_width]

        print(
            f"[composition] Static pruning: {pruned_count} pruned, "
            f"{skipped_count} resumed, {len(work_items)} to test"
        )

        if not work_items:
            ledger.finalize_campaign(policy.campaign_id, "COMPLETE",
                                    notes="All branches pruned or already tested")
            ledger.close()
            return self._make_summary(0, pruned_count, 0, 0, 0)

        # Open log
        log_dir = Path(policy.log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{policy.campaign_id}.jsonl"

        # Execute
        tested = 0
        runtime_pruned = 0
        best_score = 0
        best_result: Optional[Dict] = None
        stored_count = 0

        start_time = time.time()

        # Signal handling
        original_sigint = signal.getsignal(signal.SIGINT)

        def handle_signal(signum: int, frame: Any) -> None:
            self._interrupted = True
            print("\n[composition] Interrupt received, finishing current batch...")

        signal.signal(signal.SIGINT, handle_signal)

        try:
            with JsonlWriter(str(log_path)) as log:
                if policy.workers > 1 and len(work_items) > 1:
                    results = self._run_parallel(work_items, policy.workers)
                else:
                    results = self._run_serial(work_items)

                for result in results:
                    if self._interrupted:
                        break

                    branch_id = result["branch_id"]

                    if result.get("error"):
                        log.write({"branch_id": branch_id, "error": result["error"]})
                        continue

                    if result.get("pruned"):
                        runtime_pruned += 1
                        wi = next(
                            (w for w in work_items if w["branch_id"] == branch_id),
                            None,
                        )
                        stack_dict = wi["stack"] if wi else {}
                        ledger.record_branch(
                            branch_id=branch_id,
                            campaign_id=policy.campaign_id,
                            stack_hash=stack_dict.get("stack_hash", ""),
                            stack_json=json.dumps(stack_dict) if stack_dict else "",
                            campaign_key=stack_dict.get("campaign_key", ""),
                            peel_order=stack_dict.get("peel_order", ""),
                            status="pruned",
                            prune_type=result.get("prune_type", "heuristic"),
                            prune_reason=result.get("prune_reason", ""),
                        )
                        log.write(result)
                        continue

                    tested += 1
                    score = result.get("score", 0)

                    if score > best_score:
                        best_score = score
                        best_result = result

                    # Find the matching work item to get stack data
                    wi = next(
                        (w for w in work_items if w["branch_id"] == branch_id),
                        None,
                    )
                    stack_dict = wi["stack"] if wi else {}
                    stack_json = json.dumps(stack_dict)
                    stack_hash = stack_dict.get("stack_hash", "")
                    campaign_key = stack_dict.get("campaign_key", "")

                    storable = score >= policy.score_threshold
                    if storable:
                        stored_count += 1

                    # Always record the branch for coverage tracking.
                    # Only include plaintext/intermediate for storable results.
                    ledger.record_branch(
                        branch_id=branch_id,
                        campaign_id=policy.campaign_id,
                        stack_hash=stack_hash,
                        stack_json=stack_json,
                        campaign_key=campaign_key,
                        peel_order=stack_dict.get("peel_order", ""),
                        status="tested",
                        score=score,
                        bean_pass=result.get("bean_pass", False),
                        ic_value=result.get("ic_value"),
                        plaintext=result.get("plaintext", "") if storable else "",
                        intermediate_text=result.get("intermediate_text", "") if storable else "",
                        score_breakdown=result.get("score_breakdown") if storable else None,
                    )

                    # Detailed result row only for storable scores
                    if storable:
                        ledger.record_result(
                            campaign_id=policy.campaign_id,
                            branch_id=branch_id,
                            stack_hash=stack_hash,
                            score=score,
                            bean_pass=result.get("bean_pass", False),
                            ic_value=result.get("ic_value"),
                            plaintext=result.get("plaintext", ""),
                            intermediate_text=result.get("intermediate_text", ""),
                            score_breakdown=result.get("score_breakdown"),
                        )

                    ledger.checkpoint(policy.campaign_id, branch_id, "complete", result)
                    log.write(result)

                    # Progress
                    if tested % 100 == 0:
                        elapsed = time.time() - start_time
                        rate = tested / elapsed if elapsed > 0 else 0
                        print(
                            f"[composition] {tested}/{len(work_items)} tested, "
                            f"best={best_score}, stored={stored_count}, "
                            f"{rate:.0f}/s"
                        )

                    ledger.commit()

        finally:
            signal.signal(signal.SIGINT, original_sigint)

        # Finalize
        status = "PARTIAL" if self._interrupted else "COMPLETE"
        elapsed = time.time() - start_time
        notes = (
            f"Tested {tested}, pruned {pruned_count}+{runtime_pruned}, "
            f"stored {stored_count}, best {best_score}, {elapsed:.1f}s"
        )
        ledger.finalize_campaign(policy.campaign_id, status, notes)
        ledger.close()

        # Final report
        print(f"\n[composition] Campaign '{policy.name}' {status}")
        print(f"  Total branches:   {len(all_stacks)}")
        print(f"  Static pruned:    {pruned_count}")
        print(f"  Runtime pruned:   {runtime_pruned}")
        print(f"  Tested:           {tested}")
        print(f"  Stored (>={policy.score_threshold}): {stored_count}")
        print(f"  Best score:       {best_score}")
        print(f"  Elapsed:          {elapsed:.1f}s")
        if best_result and best_result.get("plaintext"):
            pt = best_result["plaintext"]
            print(f"  Best plaintext:   {pt[:60]}{'...' if len(pt) > 60 else ''}")

        return self._make_summary(
            tested, pruned_count + runtime_pruned, stored_count,
            best_score, elapsed,
        )

    def _run_serial(
        self,
        work_items: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Execute work items serially."""
        results: list[Dict[str, Any]] = []
        for item in work_items:
            if self._interrupted:
                break
            results.append(_worker_evaluate(item))
        return results

    def _run_parallel(
        self,
        work_items: List[Dict[str, Any]],
        workers: int,
    ) -> List[Dict[str, Any]]:
        """Execute work items in parallel using multiprocessing."""
        results: list[Dict[str, Any]] = []
        # Use imap_unordered for streaming results
        with mp.Pool(processes=workers) as pool:
            for result in pool.imap_unordered(
                _worker_evaluate,
                work_items,
                chunksize=max(1, len(work_items) // (workers * 4)),
            ):
                if self._interrupted:
                    pool.terminate()
                    break
                results.append(result)
        return results

    def preview(self) -> Dict[str, Any]:
        """Preview what the campaign would do without executing.

        Returns composition counts, pruning estimates, and work items.
        """
        all_stacks = self.enumerate_stacks()

        pruned_count = 0
        families: Dict[str, int] = {}

        for stack in all_stacks:
            key = stack.campaign_key
            families[key] = families.get(key, 0) + 1

            prune = evaluate_pruning(stack, aggressive=self.policy.aggressive_pruning,
                                     ct_length=len(self.policy.ciphertext))
            if prune.pruned:
                pruned_count += 1

        return {
            "campaign_id": self.policy.campaign_id,
            "total_stacks": len(all_stacks),
            "estimated_pruned": pruned_count,
            "estimated_to_test": len(all_stacks) - pruned_count,
            "families": families,
            "policy": self.policy.to_dict(),
        }

    @staticmethod
    def _make_summary(
        tested: int,
        pruned: int,
        stored: int,
        best_score: int,
        elapsed: float,
    ) -> Dict[str, Any]:
        return {
            "tested": tested,
            "pruned": pruned,
            "stored": stored,
            "best_score": best_score,
            "elapsed_seconds": elapsed,
        }


# ── Convenience runner ─────────────────────────────────────────────────

def run_campaign(policy: CampaignPolicy) -> Dict[str, Any]:
    """Run a composition campaign with the given policy."""
    orch = CompositionOrchestrator(policy)
    return orch.run()


def preview_campaign(policy: CampaignPolicy) -> Dict[str, Any]:
    """Preview a campaign without executing."""
    orch = CompositionOrchestrator(policy)
    return orch.preview()
