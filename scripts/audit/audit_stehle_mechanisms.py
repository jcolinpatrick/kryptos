#!/usr/bin/env python3
"""Bounded mechanism audit for the Stehle lag-4 delta-5 anomaly.

This script intentionally does not search for a solution. It asks whether the
verified local regularity can be promoted into a finite hand-executable
predicate under simple additive, grid, or null-deletion mechanisms.
"""

from __future__ import annotations

import json
from pathlib import Path

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {ch: i for i, ch in enumerate(ALPH)}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _delta(a: str, b: str) -> int:
    return (IDX[b] - IDX[a]) % 26


def _run_deltas(text: str, start: int, lag: int, pairs: int) -> list[int]:
    return [_delta(text[start + i], text[start + i + lag]) for i in range(pairs)]


def _equal_delta_runs(text: str, max_lag: int = 20) -> list[dict[str, int]]:
    runs: list[dict[str, int]] = []
    for lag in range(1, max_lag + 1):
        diffs = [_delta(text[i], text[i + lag]) for i in range(len(text) - lag)]
        if not diffs:
            continue
        start = 0
        current = diffs[0]
        for i, d in enumerate(diffs[1:], start=1):
            if d == current:
                continue
            run = i - start
            if run >= 4:
                runs.append({"start": start, "lag": lag, "delta": current, "run": run})
            start = i
            current = d
        run = len(diffs) - start
        if run >= 4:
            runs.append({"start": start, "lag": lag, "delta": current, "run": run})
    return sorted(runs, key=lambda r: (-r["run"], r["lag"], r["start"], r["delta"]))


def _grid_vectors(start: int, lag: int, pairs: int, widths: list[int]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for width in widths:
        vectors: list[list[int]] = []
        coords: list[list[list[int]]] = []
        for i in range(pairs):
            a = start + i
            b = a + lag
            ar, ac = divmod(a, width)
            br, bc = divmod(b, width)
            vectors.append([br - ar, bc - ac])
            coords.append([[ar, ac], [br, bc]])
        out.append({
            "width": width,
            "pair_coords": coords,
            "vectors": vectors,
            "constant_vector": len({tuple(v) for v in vectors}) == 1,
        })
    return out


def _single_deletion_scan(text: str, max_lag: int = 20) -> dict[str, object]:
    preserving_exact = []
    best_by_deletion = []
    for pos in range(len(text)):
        deleted = text[:pos] + text[pos + 1:]
        runs = _equal_delta_runs(deleted, max_lag=max_lag)
        best = runs[0] if runs else {"run": 1}
        if best.get("run", 0) >= 5:
            best_by_deletion.append({"deleted_pos": pos, "best": best})
        for r in runs:
            if r["lag"] == 4 and r["delta"] == 5 and r["run"] >= 5:
                preserving_exact.append({"deleted_pos": pos, "run": r})
                break
    return {
        "deletions_preserving_a_lag4_delta5_run_ge5": preserving_exact,
        "deletions_with_any_equal_delta_run_ge5": best_by_deletion,
        "window_internal_deletions_preserve_exact": [
            item for item in preserving_exact if 55 <= item["deleted_pos"] <= 63
        ],
    }


def _same_row_lag_scan(text: str, width: int, lag: int) -> dict[str, object]:
    pairs = []
    for pos in range(len(text) - lag):
        if pos // width != (pos + lag) // width:
            continue
        d = _delta(text[pos], text[pos + lag])
        pairs.append({"pos": pos, "pair": [pos, pos + lag], "delta": d})
    deltas = sorted({item["delta"] for item in pairs})
    return {
        "width": width,
        "lag": lag,
        "same_row_pair_count": len(pairs),
        "distinct_deltas": deltas,
        "delta5_pair_count": sum(1 for item in pairs if item["delta"] == 5),
        "all_same_row_pairs_delta5": bool(pairs) and deltas == [5],
        "stehle_pairs": [
            item for item in pairs if 55 <= item["pos"] <= 59
        ],
    }


def _finite_family_falsifications(text: str) -> list[dict[str, object]]:
    width21 = _same_row_lag_scan(text, width=21, lag=4)
    width5 = _same_row_lag_scan(text, width=5, lag=4)
    deletion_scan = _single_deletion_scan(text, max_lag=20)
    return [
        {
            "family": "width21_same_row_lag4_forces_delta5",
            "tested_universe": "all same-row lag-4 pairs in the CT97 width-21 grid",
            "candidate_predicate": "same row and four columns apart implies ciphertext delta 5",
            "falsified": not width21["all_same_row_pairs_delta5"],
            "evidence": width21,
            "epistemic_result": "width-21 geometry describes the Stehle pair layout but does not force delta=5",
        },
        {
            "family": "mod5_same_row_lag4_forces_delta5",
            "tested_universe": "all same-row lag-4 pairs in width-5 rows",
            "candidate_predicate": "mod-5 row geometry implies ciphertext delta 5",
            "falsified": not width5["all_same_row_pairs_delta5"],
            "evidence": width5,
            "epistemic_result": "mod-5 geometry is not a hard delta predicate",
        },
        {
            "family": "single_null_deletion_explains_required_lag4_delta5",
            "tested_universe": "all 97 single-position deletions followed by equal-delta scans up to lag 20",
            "candidate_predicate": "one inserted null creates or preserves a required lag-4 delta-5 run",
            "falsified": len(deletion_scan["window_internal_deletions_preserve_exact"]) == 0,
            "evidence": {
                "window_internal_deletions_preserve_exact": deletion_scan["window_internal_deletions_preserve_exact"],
                "deletions_preserving_a_lag4_delta5_run_ge5_count": len(deletion_scan["deletions_preserving_a_lag4_delta5_run_ge5"]),
            },
            "epistemic_result": "single-deletion null handling does not produce a usable hard predicate",
        },
    ]


def run_audit() -> dict[str, object]:
    from kryptos.kernel.constants import CRIB_DICT, CT

    start, lag, pairs = 55, 4, 5
    observed = {
        "zero_indexed_window": [start, start + 2 * lag],
        "substring": CT[start:start + 2 * lag + 1],
        "lag": lag,
        "deltas": _run_deltas(CT, start, lag, pairs),
    }
    crib_overlap = []
    for i in range(pairs):
        a, b = start + i, start + i + lag
        crib_overlap.append({
            "pair": [a, b],
            "crib_a": CRIB_DICT.get(a),
            "crib_b": CRIB_DICT.get(b),
            "both_endpoints_known": a in CRIB_DICT and b in CRIB_DICT,
        })

    all_runs = _equal_delta_runs(CT, max_lag=20)
    exact_runs = [
        r for r in all_runs if r["lag"] == lag and r["delta"] == 5 and r["run"] >= pairs
    ]
    result = {
        "schema_version": 1,
        "claim": "Stehle mechanism exploitability",
        "observed": observed,
        "additive_leakage": {
            "relations": {
                "vigenere": "C[i+4]-C[i]=5 implies (P[i+4]-P[i]) + (K[i+4]-K[i]) = 5 mod 26",
                "beaufort": "C[i+4]-C[i]=5 implies (K[i+4]-K[i]) - (P[i+4]-P[i]) = 5 mod 26",
                "variant_beaufort": "C[i+4]-C[i]=5 implies (P[i+4]-P[i]) - (K[i+4]-K[i]) = 5 mod 26",
            },
            "crib_overlap": crib_overlap,
            "constraint_on_noncrib_keystream": False,
            "reason": "No lag-4 pair has both plaintext endpoints known; only position 63 is a crib endpoint.",
        },
        "grid_families": {
            "widths_tested": [5, 10, 15, 20, 21],
            "pair_vectors": _grid_vectors(start, lag, pairs, [5, 10, 15, 20, 21]),
            "mechanism_predicate_found": False,
            "reason": "Width 21 gives a same-row lag-4 description, but that is geometry only; it does not force delta=5.",
        },
        "equal_delta_scan": {
            "max_lag": 20,
            "top_runs": all_runs[:20],
            "exact_lag4_delta5_runs": exact_runs,
        },
        "single_deletion_null_scan": _single_deletion_scan(CT, max_lag=20),
        "finite_family_falsifications": _finite_family_falsifications(CT),
        "conclusion": {
            "hard_cryptanalytic_constraint": False,
            "soft_ranking_feature": True,
            "local_anomaly_no_current_exploit": True,
            "post_hoc_coincidence_not_excluded": True,
            "summary": (
                "The Stehle pattern is real and statistically describable, but "
                "these bounded tests do not produce a hand-executable mechanism "
                "for which valid candidates must preserve or explain it."
            ),
        },
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/audit_stehle_mechanisms.py",
    }
    return result


def write_outputs(result: dict[str, object]) -> None:
    root = _repo_root()
    results_dir = root / "results" / "audit"
    docs_dir = root / "docs" / "audits"
    results_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)
    json_path = results_dir / "stehle_mechanism_audit.json"
    md_path = docs_dir / "stehle_mechanism_audit.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    conclusion = result["conclusion"]  # type: ignore[index]
    observed = result["observed"]  # type: ignore[index]
    md_path.write_text(
        "\n".join([
            "# Stehle Mechanism Audit",
            "",
            "## Verdict",
            "",
            f"- Hard cryptanalytic constraint: {conclusion['hard_cryptanalytic_constraint']}",
            f"- Soft ranking feature: {conclusion['soft_ranking_feature']}",
            f"- Local anomaly with no current exploit: {conclusion['local_anomaly_no_current_exploit']}",
            "",
            "## Observed",
            "",
            f"- Substring: `{observed['substring']}`",
            f"- Lag-4 deltas: {observed['deltas']}",
            "",
            "## Mechanism Findings",
            "",
            "- Additive leakage gives algebraic relations, but no lag-4 pair has both plaintext endpoints known.",
            "- Width 21 explains the five pairs as same-row lag-4 geometry, but not the delta value.",
            "- Single-deletion null scans do not produce a predicate that candidates must satisfy.",
            "- Finite predicate checks falsify geometry-only explanations such as width-21 same-row lag-4 implies delta 5.",
            "",
            "## Reproduction",
            "",
            "```bash",
            str(result["reproduction_command"]),
            "```",
            "",
        ]) + "\n"
    )


def main() -> None:
    result = run_audit()
    write_outputs(result)
    print(json.dumps({
        "wrote": [
            str(_repo_root() / "results" / "audit" / "stehle_mechanism_audit.json"),
            str(_repo_root() / "docs" / "audits" / "stehle_mechanism_audit.md"),
        ],
        "hard_constraint": result["conclusion"]["hard_cryptanalytic_constraint"],  # type: ignore[index]
    }, indent=2))


if __name__ == "__main__":
    main()
