"""Benchmark runner — execute suite cases, optionally in parallel."""
from __future__ import annotations

import importlib.util
import time
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Dict, List

from bench.schema import BenchmarkCase, BenchmarkResult, CandidateResult


# ---------------------------------------------------------------------------
# Helpers (module-level for multiprocessing pickle compatibility)
# ---------------------------------------------------------------------------

def _load_attack_fn(script_path: str):
    """Dynamically import a script and return its ``attack()`` callable.

    Returns ``None`` when the script lacks an ``attack`` attribute.
    """
    path = Path(script_path).resolve()
    spec = importlib.util.spec_from_file_location(f"bench_{path.stem}", str(path))
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return getattr(module, "attack", None)


def _parse_family(script_path: str) -> str:
    """Extract ``Family:`` from a script's metadata header, or ``""``."""
    try:
        with open(script_path) as f:
            header = f.read(2048)
        for line in header.split("\n"):
            stripped = line.strip()
            if stripped.startswith("Family:"):
                return stripped.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def _run_one(args: Dict[str, Any]) -> Dict[str, Any]:
    """Worker: run a single benchmark case and return a raw result dict.

    Must stay at module level so ``multiprocessing.Pool`` can pickle it.
    """
    case_id = args["case_id"]
    ciphertext = args["ciphertext"]
    script = args["script"]
    params = args.get("params", {})
    expected_pt = args.get("expected_plaintext", "")
    top_k = args.get("top_k", 5)

    t0 = time.time()
    try:
        attack_fn = _load_attack_fn(script)
        if attack_fn is None:
            return {
                "case_id": case_id,
                "status": "error",
                "elapsed_s": time.time() - t0,
                "error": f"No attack() function in {script}",
                "script": script,
                "ciphertext": ciphertext,
            }

        raw_results = attack_fn(ciphertext, **params)
        elapsed = time.time() - t0

        if not isinstance(raw_results, list) or not raw_results:
            return {
                "case_id": case_id,
                "status": "no_results",
                "elapsed_s": elapsed,
                "n_candidates": 0,
                "script": script,
                "ciphertext": ciphertext,
            }

        # Score top-K through canonical path
        from kryptos.kernel.scoring.aggregate import score_candidate

        top_candidates = []
        for score_val, pt, method in raw_results[:top_k]:
            sb = score_candidate(pt)
            top_candidates.append({
                "score": score_val,
                "plaintext": pt,
                "method": method,
                "canonical_score": sb.to_dict(),
            })

        # Predicted plaintext = top-1
        predicted_pt = raw_results[0][1]

        # Check match across ALL results (not just top-K)
        match = False
        match_rank = -1
        if expected_pt:
            for i, (_, pt, _) in enumerate(raw_results):
                if pt == expected_pt:
                    match = True
                    match_rank = i + 1  # 1-indexed
                    break

        family = _parse_family(script)

        result_dict = {
            "case_id": case_id,
            "status": "success",
            "elapsed_s": elapsed,
            "n_candidates": len(raw_results),
            "top_candidates": top_candidates,
            "predicted_plaintext": predicted_pt,
            "predicted_family": family,
            "match_plaintext": match,
            "match_rank": match_rank,
            "script": script,
            "ciphertext": ciphertext,
        }

        # Segmentation analysis on the input ciphertext
        from bench.segmenter import segment_ciphertext
        seg_result = segment_ciphertext(ciphertext)
        result_dict["segmentation"] = seg_result.to_dict()

        # Post-selection validation (segmentation-aware)
        from bench.validator import validate_result
        validate_result(result_dict)

        return result_dict

    except Exception as e:
        return {
            "case_id": case_id,
            "status": "error",
            "elapsed_s": time.time() - t0,
            "error": f"{type(e).__name__}: {e}",
            "script": script,
            "ciphertext": ciphertext,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_suite(
    cases: List[BenchmarkCase],
    *,
    parallel: int = 1,
    top_k: int = 5,
) -> List[BenchmarkResult]:
    """Run all cases in a benchmark suite.

    Args:
        cases: Cases to execute.
        parallel: Worker count (1 = sequential, no multiprocessing overhead).
        top_k: How many top candidates to retain per case.

    Returns:
        One ``BenchmarkResult`` per input case.  Order may differ when
        *parallel* > 1.
    """
    work_items = [
        {
            "case_id": c.case_id,
            "ciphertext": c.ciphertext,
            "script": c.script,
            "params": c.params,
            "expected_plaintext": c.expected_plaintext,
            "top_k": top_k,
        }
        for c in cases
    ]

    if parallel <= 1:
        raw_dicts = [_run_one(item) for item in work_items]
    else:
        with Pool(processes=parallel) as pool:
            raw_dicts = list(pool.imap_unordered(_run_one, work_items))

    return [_dict_to_result(d) for d in raw_dicts]


def _dict_to_result(raw: Dict[str, Any]) -> BenchmarkResult:
    candidates = [
        CandidateResult(
            score=c["score"],
            plaintext=c["plaintext"],
            method=c["method"],
            canonical_score=c.get("canonical_score"),
        )
        for c in raw.get("top_candidates", [])
    ]
    return BenchmarkResult(
        case_id=raw["case_id"],
        status=raw["status"],
        elapsed_s=raw.get("elapsed_s", 0.0),
        n_candidates=raw.get("n_candidates", 0),
        top_candidates=candidates,
        predicted_plaintext=raw.get("predicted_plaintext", ""),
        predicted_family=raw.get("predicted_family", ""),
        match_plaintext=raw.get("match_plaintext", False),
        match_rank=raw.get("match_rank", -1),
        error=raw.get("error", ""),
        script=raw.get("script", ""),
        ciphertext=raw.get("ciphertext", ""),
        validation=raw.get("validation", {}),
        segmentation=raw.get("segmentation", {}),
    )
