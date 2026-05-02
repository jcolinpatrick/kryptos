#!/usr/bin/env python3
"""Audit finite elimination harness accounting and checkpoint/resume semantics."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULT_PATH = REPO_ROOT / "results" / "audit" / "elimination_harness_accounting.json"
DOC_PATH = REPO_ROOT / "docs" / "audits" / "elimination_harness_accounting.md"
HYPOTHESIS_TESTS = REPO_ROOT / "scripts" / "hypothesis_tests"

if str(HYPOTHESIS_TESTS) not in sys.path:
    sys.path.insert(0, str(HYPOTHESIS_TESTS))

import h_624_73_nullmask_harness as nullmask  # noqa: E402
import h_624_nonword_key_schedule_harness as nonword  # noqa: E402
import h_pretransposition_layer_harness as pretransposition  # noqa: E402


def _run_main(module: Any, argv: list[str]) -> int:
    """Run a noisy harness main while preserving a clean audit stdout."""
    with contextlib.redirect_stdout(io.StringIO()):
        rc = module.main(argv)
    return int(rc or 0)


def _inventory_total(doc: dict[str, Any]) -> int:
    return int(doc.get("inventory", {}).get("total_configs", -1))


def _audit_processed(doc: dict[str, Any]) -> int:
    return int(doc.get("audit_counters", {}).get("processed_count", -1))


def _coverage(doc: dict[str, Any]) -> dict[str, int]:
    cov = doc.get("coverage", {})
    return {
        "tested": int(cov.get("tested", -1)),
        "total": int(cov.get("total", -1)),
    }


def _notes_clean(doc: dict[str, Any]) -> bool:
    return not any("audit mismatch" in note for note in doc.get("notes", []))


def _status_ok_for_coverage(doc: dict[str, Any]) -> bool:
    cov = _coverage(doc)
    status = doc.get("status")
    if cov["tested"] < cov["total"]:
        return status == "INCONCLUSIVE_BUDGET"
    return status in {"ELIMINATED", "CANDIDATE_SIGNAL"}


def _summarize_doc(doc: dict[str, Any]) -> dict[str, Any]:
    cov = _coverage(doc)
    return {
        "status": doc.get("status"),
        "coverage": doc.get("coverage", {}),
        "inventory_total_configs": _inventory_total(doc),
        "audit_processed": _audit_processed(doc),
        "completed_mask_indices": doc.get("completed_mask_indices", []),
        "notes": doc.get("notes", []),
        "invariants": {
            "coverage_total_matches_inventory": cov["total"] == _inventory_total(doc),
            "coverage_tested_matches_audit_processed": cov["tested"] == _audit_processed(doc),
            "status_matches_coverage": _status_ok_for_coverage(doc),
            "no_audit_mismatch_notes": _notes_clean(doc),
        },
    }


def _run_harness(
    module: Any,
    tmpdir: Path,
    label: str,
    args: list[str],
    *,
    checkpoint: Path | None = None,
    output_name: str = "result.json",
) -> tuple[int, dict[str, Any], Path]:
    out = tmpdir / f"{label}_{output_name}"
    ckpt = checkpoint or (tmpdir / f"{label}_checkpoint.json")
    argv = [*args, "--output", str(out), "--checkpoint", str(ckpt)]
    rc = _run_main(module, argv)
    return rc, json.loads(out.read_text()), ckpt


HARNESS_CONFIGS: list[dict[str, Any]] = [
    {
        "id": "h_624_73_nullmask",
        "module": nullmask,
        "full_args": ["--mode", "smoke", "--workers", "1", "--limit-masks", "2", "--limit-keys", "3"],
        "partial_args": [
            "--mode", "smoke", "--workers", "1", "--limit-masks", "4",
            "--limit-keys", "6", "--key-chunk-size", "2", "--max-configs", "24",
        ],
        "resume_args": [
            "--mode", "smoke", "--workers", "1", "--limit-masks", "4",
            "--limit-keys", "6", "--key-chunk-size", "2", "--resume",
        ],
    },
    {
        "id": "h_pretransposition_layer",
        "module": pretransposition,
        "full_args": [
            "--mode", "smoke", "--workers", "1", "--limit-masks", "2",
            "--limit-transpositions", "5",
        ],
        "partial_args": [
            "--mode", "smoke", "--workers", "1", "--limit-masks", "3",
            "--limit-transpositions", "8", "--chunk-size", "2", "--max-configs", "12",
        ],
        "resume_args": [
            "--mode", "smoke", "--workers", "1", "--limit-masks", "3",
            "--limit-transpositions", "8", "--chunk-size", "2", "--resume",
        ],
    },
    {
        "id": "h_624_nonword_key_schedule",
        "module": nonword,
        "full_args": [
            "--mode", "smoke", "--workers", "1", "--limit-masks", "2",
            "--limit-schedules", "6", "--vimark-limit", "10",
        ],
        "partial_args": [
            "--mode", "smoke", "--workers", "1", "--limit-masks", "4",
            "--limit-schedules", "8", "--vimark-limit", "20",
            "--key-chunk-size", "2", "--max-configs", "24",
        ],
        "resume_args": [
            "--mode", "smoke", "--workers", "1", "--limit-masks", "4",
            "--limit-schedules", "8", "--vimark-limit", "20",
            "--key-chunk-size", "2", "--resume",
        ],
    },
]


def _all_invariants(summary: dict[str, Any]) -> bool:
    return all(bool(v) for v in summary.get("invariants", {}).values())


def run_audit() -> dict[str, Any]:
    harnesses: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="kryptos_elim_audit_") as td:
        tmpdir = Path(td)
        for config in HARNESS_CONFIGS:
            label = config["id"]
            module = config["module"]
            full_rc, full_doc, _ = _run_harness(module, tmpdir, f"{label}_full", config["full_args"])
            partial_ckpt = tmpdir / f"{label}_resume_checkpoint.json"
            partial_rc, partial_doc, _ = _run_harness(
                module,
                tmpdir,
                f"{label}_partial",
                config["partial_args"],
                checkpoint=partial_ckpt,
            )
            resume_rc, resume_doc, _ = _run_harness(
                module,
                tmpdir,
                f"{label}_resume",
                config["resume_args"],
                checkpoint=partial_ckpt,
            )

            # Hash-mismatch refusal: mutate a completed full checkpoint and resume.
            mismatch_ckpt = tmpdir / f"{label}_mismatch_checkpoint.json"
            _, _, _ = _run_harness(
                module,
                tmpdir,
                f"{label}_mismatch_seed",
                config["full_args"],
                checkpoint=mismatch_ckpt,
            )
            mismatch_data = json.loads(mismatch_ckpt.read_text())
            mismatch_data["assumptions_hash"] = "codex-mutated-for-audit"
            mismatch_ckpt.write_text(json.dumps(mismatch_data))
            mismatch_args = [*config["full_args"], "--resume"]
            mismatch_rc, mismatch_doc, _ = _run_harness(
                module,
                tmpdir,
                f"{label}_mismatch",
                mismatch_args,
                checkpoint=mismatch_ckpt,
            )

            full = _summarize_doc(full_doc)
            partial = _summarize_doc(partial_doc)
            resume = _summarize_doc(resume_doc)
            mismatch = {
                "status": mismatch_doc.get("status"),
                "notes": mismatch_doc.get("notes", []),
                "invariants": {
                    "hash_mismatch_refused": (
                        mismatch_doc.get("status") == "ERROR"
                        or any("hash mismatch" in note for note in mismatch_doc.get("notes", []))
                    )
                },
            }
            harnesses.append({
                "id": label,
                "return_codes": {
                    "full": full_rc,
                    "partial": partial_rc,
                    "resume": resume_rc,
                    "mismatch": mismatch_rc,
                },
                "full": full,
                "partial": partial,
                "resume": resume,
                "mismatch": mismatch,
                "resume_invariants": {
                    "partial_was_inconclusive_budget": partial_doc.get("status") == "INCONCLUSIVE_BUDGET",
                    "resume_reached_full_coverage": (
                        _coverage(resume_doc)["tested"] == _coverage(resume_doc)["total"]
                    ),
                    "resume_did_not_drop_completed_masks": set(partial_doc.get("completed_mask_indices", []))
                    <= set(resume_doc.get("completed_mask_indices", [])),
                    "resume_audit_processed_matches_coverage": (
                        _audit_processed(resume_doc) == _coverage(resume_doc)["tested"]
                    ),
                },
            })

    for h in harnesses:
        h["passed"] = (
            h["return_codes"] == {"full": 0, "partial": 0, "resume": 0, "mismatch": 0}
            and _all_invariants(h["full"])
            and _all_invariants(h["partial"])
            and _all_invariants(h["resume"])
            and all(h["resume_invariants"].values())
            and all(h["mismatch"]["invariants"].values())
        )

    return {
        "schema_version": 1,
        "claim": "elimination harness accounting and resume semantics",
        "harnesses": harnesses,
        "all_passed": all(h["passed"] for h in harnesses),
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/audit_elimination_harness_accounting.py",
    }


def write_markdown(payload: dict[str, Any]) -> None:
    lines = [
        "# Elimination Harness Accounting Audit",
        "",
        "## Verdict",
        "",
        f"- All probes passed: {payload['all_passed']}",
        "- A full smoke run must have `coverage.tested == coverage.total == inventory.total_configs`.",
        "- A partial budgeted run must be `INCONCLUSIVE_BUDGET`, not eliminated.",
        "- A resumed run must reach full coverage without dropping completed masks.",
        "- A checkpoint hash mismatch must be refused or explicitly reported.",
        "",
        "## Harnesses",
        "",
    ]
    for h in payload["harnesses"]:
        lines += [
            f"### {h['id']}",
            "",
            f"- Passed: {h['passed']}",
            f"- Full status: {h['full']['status']} coverage={h['full']['coverage']}",
            f"- Partial status: {h['partial']['status']} coverage={h['partial']['coverage']}",
            f"- Resume status: {h['resume']['status']} coverage={h['resume']['coverage']}",
            f"- Mismatch status: {h['mismatch']['status']}",
            "",
        ]
    lines += [
        "## Reproduction",
        "",
        "```bash",
        str(payload["reproduction_command"]),
        "```",
        "",
    ]
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text("\n".join(lines))


def main() -> int:
    payload = run_audit()
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_markdown(payload)
    print(json.dumps({
        "wrote": [str(RESULT_PATH), str(DOC_PATH)],
        "all_passed": payload["all_passed"],
        "harness_count": len(payload["harnesses"]),
    }, indent=2))
    return 0 if payload["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
