#!/usr/bin/env python3
"""Search for epistemic-provenance leakage in code and docs."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULT_PATH = REPO_ROOT / "results" / "audit" / "provenance_leakage.json"
DOC_PATH = REPO_ROOT / "docs" / "audits" / "provenance_leakage.md"

TERMS = [
    "624",
    "p≈1/642",
    "1/642",
    "p≈1/5520",
    "1/5520",
    "fingerprint",
    "must explain",
    "hard constraint",
    "Bean",
    "Stehle",
    "retired",
    "null palette",
    "H1",
]

EXCLUDED_DIR_PARTS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "venv",
    "copy",
    "archive",
    "results",
    "artifacts",
}

POLICY_SAFE_PATHS = {
    "kryptosbot/claim_policy.py",
    "kryptosbot/claim_rendering.py",
    "kryptosbot/claims_registry.py",
    "kryptosbot/EPISTEMIC_PROVENANCE.md",
    "docs/claims_registry.json",
    "docs/methodological_audits.md",
}


def iter_files() -> list[Path]:
    out = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT)
        if any(part in EXCLUDED_DIR_PARTS for part in rel.parts):
            continue
        if path.suffix.lower() not in {".py", ".md", ".json", ".txt"}:
            continue
        out.append(path)
    return sorted(out)


def scan() -> dict[str, Any]:
    pattern = re.compile("|".join(re.escape(term) for term in TERMS), re.IGNORECASE)
    hits = []
    for path in iter_files():
        rel = str(path.relative_to(REPO_ROOT))
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not pattern.search(line):
                continue
            lower = line.lower()
            policy_routed = (
                rel in POLICY_SAFE_PATHS
                or "render_claim" in line
                or "claim_policy" in line
                or "can_use_as_" in line
                or "can_promote_to_must_explain" in line
            )
            severity = "info"
            if not policy_routed:
                if "fingerprint" in lower or "must explain" in lower or "hard constraint" in lower:
                    severity = "high"
                elif "1/642" in lower or "1/5520" in lower or "stehle" in lower:
                    severity = "medium"
                elif "retired" in lower or "null palette" in lower:
                    severity = "medium"
            hits.append({
                "path": rel,
                "line": lineno,
                "text": line.strip()[:500],
                "policy_routed_or_registry": policy_routed,
                "severity": severity,
            })
    high_risk = [h for h in hits if h["severity"] in {"high", "medium"} and not h["policy_routed_or_registry"]]
    return {
        "terms": TERMS,
        "hit_count": len(hits),
        "high_risk_count": len(high_risk),
        "high_risk_hits": high_risk[:300],
        "all_hits_truncated": hits[:1000],
    }


def inspect_prompt_guards() -> dict[str, Any]:
    pantheon = (REPO_ROOT / "kryptosbot" / "pantheon.py").read_text(errors="replace")
    api_client = (REPO_ROOT / "kryptosbot" / "api_client.py").read_text(errors="replace")
    return {
        "pantheon_agent_prompts_have_guardrail": "Project Provenance Guardrail" in pantheon
        and "_guarded_agent_body" in pantheon,
        "api_prompt_bean_section_soft_context": "Soft Context, Not Constraints" in api_client
        and "_PROMPT_BEAN_MINOR_DIFFS" in api_client,
        "api_prompt_removed_substitution_layer_constraint_language": (
            "They constrain the substitution layer" not in api_client
        ),
    }


def write_markdown(payload: dict[str, Any]) -> None:
    lines = [
        "# Provenance Leakage Audit",
        "",
        "## Verdict",
        "",
        f"- Total high-risk un-routed hits: {payload['high_risk_count']}",
        "- Registry and policy files contain expected uses of the searched terms.",
        "- Any un-routed `fingerprint`, `hard constraint`, p-value, or retired-claim language should be treated as a prompt/doc hardening target.",
        f"- Pantheon prompt guardrail present: {payload['prompt_guards']['pantheon_agent_prompts_have_guardrail']}",
        f"- API prompt Bean section downgraded: {payload['prompt_guards']['api_prompt_bean_section_soft_context']}",
        "",
        "## Highest-Risk Hits",
        "",
    ]
    for hit in payload["high_risk_hits"][:40]:
        lines.append(f"- `{hit['path']}:{hit['line']}` [{hit['severity']}]: {hit['text']}")
    lines += [
        "",
        "## Reproduction",
        "",
        "```bash",
        "PYTHONPATH=src python3 scripts/audit/audit_provenance_leakage.py",
        "```",
    ]
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text("\n".join(lines) + "\n")


def main() -> int:
    payload = {
        "schema_version": 1,
        "scan": scan(),
        "prompt_guards": inspect_prompt_guards(),
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/audit_provenance_leakage.py",
    }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    write_markdown({**payload["scan"], "prompt_guards": payload["prompt_guards"]})
    print(json.dumps({
        "wrote": [str(RESULT_PATH), str(DOC_PATH)],
        "high_risk": payload["scan"]["high_risk_count"],
        "prompt_guards": payload["prompt_guards"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
