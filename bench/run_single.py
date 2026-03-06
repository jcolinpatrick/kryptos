#!/usr/bin/env python3
"""Minimal benchmark wrapper: run one attack script or score one plaintext.

Usage:
    # Run an attack script against K4 ciphertext
    PYTHONPATH=src python bench/run_single.py --script scripts/examples/e_caesar_standard.py

    # Run against custom ciphertext
    PYTHONPATH=src python bench/run_single.py --script scripts/examples/e_caesar_standard.py --ct ABCDEF

    # Score a known plaintext directly (no attack script)
    PYTHONPATH=src python bench/run_single.py --eval-only --pt WEAREDISCOVEREDSAVEYOURSELF

Output: JSON to stdout. Exit code 0 if results found, 1 otherwise.
"""
import argparse
import importlib.util
import json
import sys
import time
from pathlib import Path


def load_attack(script_path: str):
    """Dynamically import a script and return its attack() function."""
    path = Path(script_path).resolve()
    if not path.exists():
        print(f"Error: script not found: {path}", file=sys.stderr)
        sys.exit(1)
    spec = importlib.util.spec_from_file_location(f"attack_{path.stem}", str(path))
    if spec is None or spec.loader is None:
        print(f"Error: cannot load {path}", file=sys.stderr)
        sys.exit(1)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, "attack", None)
    if fn is None:
        print(f"Error: {path.name} has no attack() function", file=sys.stderr)
        sys.exit(1)
    return fn


def score_plaintext(pt: str) -> dict:
    """Score a plaintext through both canonical scorers."""
    from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

    sb = score_candidate(pt)
    fsb = score_candidate_free(pt)
    return {
        "plaintext": pt,
        "anchored": sb.to_dict(),
        "anchored_summary": sb.summary,
        "free": fsb.to_dict(),
        "free_summary": fsb.summary,
    }


def main():
    parser = argparse.ArgumentParser(description="Run one attack or score one plaintext")
    parser.add_argument("--script", help="Path to attack script with attack() function")
    parser.add_argument("--ct", help="Ciphertext (default: K4 from constants)")
    parser.add_argument("--eval-only", action="store_true", help="Score a plaintext, no attack")
    parser.add_argument("--pt", help="Plaintext to score (with --eval-only)")
    parser.add_argument("--top", type=int, default=5, help="Max results to output (default: 5)")
    args = parser.parse_args()

    if args.eval_only:
        if not args.pt:
            parser.error("--eval-only requires --pt")
        result = score_plaintext(args.pt.upper())
        json.dump(result, sys.stdout, indent=2)
        print()
        sys.exit(0)

    if not args.script:
        parser.error("--script is required (or use --eval-only --pt TEXT)")

    # Determine ciphertext
    if args.ct:
        ct = args.ct.upper()
    else:
        from kryptos.kernel.constants import CT
        ct = CT

    # Run attack
    attack_fn = load_attack(args.script)
    t0 = time.time()
    results = attack_fn(ct)
    elapsed = time.time() - t0

    if not isinstance(results, list) or not results:
        json.dump({"script": args.script, "elapsed_s": elapsed, "results": []}, sys.stdout, indent=2)
        print()
        sys.exit(1)

    # Score top results through canonical path
    from kryptos.kernel.scoring.aggregate import score_candidate

    output_results = []
    for score_val, pt, method in results[: args.top]:
        sb = score_candidate(pt)
        output_results.append({
            "attack_score": score_val,
            "method": method,
            "plaintext": pt[:80],
            "canonical": sb.to_dict(),
            "summary": sb.summary,
        })

    output = {
        "script": args.script,
        "ciphertext": ct[:40] + ("..." if len(ct) > 40 else ""),
        "elapsed_s": round(elapsed, 3),
        "n_results": len(results),
        "results": output_results,
    }
    json.dump(output, sys.stdout, indent=2)
    print()
    sys.exit(0)


if __name__ == "__main__":
    main()
