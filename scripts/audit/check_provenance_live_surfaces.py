#!/usr/bin/env python3
"""CI-suitable check for provenance leakage on live prompt/control surfaces."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULT_PATH = REPO_ROOT / "results" / "audit" / "provenance_live_surface_check.json"
DOC_PATH = REPO_ROOT / "docs" / "audits" / "provenance_live_surface_check.md"

NULL_PALETTE_SURFACES = [
    ".claude/agents/keystream-forensics.md",
    ".claude/agents/stego-analyst.md",
    ".claude/skills/cipher-beaufort/SKILL.md",
    ".claude/skills/cipher-running-key-beaufort/SKILL.md",
    ".claude/skills/k4-stego-cracker/SKILL.md",
    ".claude/skills/otp-null-keystream-forensics/SKILL.md",
]


def _read(rel: str) -> str:
    path = REPO_ROOT / rel
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


def _line_hits(path: Path, patterns: list[re.Pattern[str]]) -> list[dict[str, Any]]:
    hits = []
    lines = path.read_text(errors="replace").splitlines()
    for idx, line in enumerate(lines):
        lineno = idx + 1
        lower = line.lower()
        context = "\n".join(lines[max(0, idx - 1): min(len(lines), idx + 2)]).lower()
        hedged_policy_line = any(
            token in context
            for token in (
                "without current provenance",
                "without provenance-policy",
                "without formal rehabilitation",
                "not a must-explain",
                "not a valid reason",
                "not a hard constraint",
                "do not use",
                "must not",
                "not be revived",
            )
        )
        for pattern in patterns:
            if pattern.search(lower):
                if hedged_policy_line and (
                    "must explain" in lower
                    or "must-explain" in lower
                    or "hard constraint" in lower
                ):
                    continue
                hits.append({"path": str(path.relative_to(REPO_ROOT)), "line": lineno, "text": line.strip()[:300]})
    return hits


def _scan_live_prompt_directory() -> list[dict[str, Any]]:
    """Flag exact promotion phrases that should not appear in live prompts."""
    patterns = [
        re.compile(r"strongest statistical signal linking"),
        re.compile(r"cipher fingerprint"),
        re.compile(r"weakness to exploit"),
        re.compile(r"\bmust explain\b"),
        re.compile(r"\bmust-explain\b"),
    ]
    hits = []
    for base in (REPO_ROOT / ".claude" / "agents", REPO_ROOT / ".claude" / "skills"):
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.md")):
            if "agent-memory" in path.parts:
                continue
            hits.extend(_line_hits(path, patterns))
    return hits


def run_check() -> dict[str, Any]:
    pantheon = _read("kryptosbot/pantheon.py")
    api_client = _read("kryptosbot/api_client.py")
    registries = _read("kryptosbot/registries.py")

    violations: list[dict[str, Any]] = []

    guard_checks = {
        "pantheon_guardrail_present": "Project Provenance Guardrail" in pantheon,
        "pantheon_archival_memory_quarantine_present": ".claude/agent-memory/" in pantheon
        and "archival evidence only" in pantheon,
        "api_bean_section_soft_context": "Soft Context, Not Constraints" in api_client,
        "api_substitution_layer_hard_constraint_removed": "They constrain the substitution layer" not in api_client,
        "stehle_registry_not_fingerprint": "cipher fingerprint" not in registries.lower()
        and "weakness to exploit" not in registries.lower(),
    }
    for check, ok in guard_checks.items():
        if not ok:
            violations.append({"type": "guard_check_failed", "check": check})

    palette_surface_results = []
    for rel in NULL_PALETTE_SURFACES:
        text = _read(rel)
        lower = text.lower()
        ok = bool(text) and "retired" in lower and "hard constraint" in lower and (
            "must-explain" in lower or "must explain" in lower
        )
        no_promotion = "strongest statistical signal linking" not in lower
        palette_surface_results.append({"path": rel, "quarantined": ok, "no_promotion_phrase": no_promotion})
        if not ok or not no_promotion:
            violations.append({
                "type": "null_palette_surface_not_quarantined",
                "path": rel,
                "quarantined": ok,
                "no_promotion_phrase": no_promotion,
            })

    prompt_phrase_hits = _scan_live_prompt_directory()
    for hit in prompt_phrase_hits:
        violations.append({"type": "live_prompt_promotion_phrase", **hit})

    return {
        "schema_version": 1,
        "claim": "live prompt/control surfaces do not promote retired or statistical claims beyond policy",
        "guard_checks": guard_checks,
        "null_palette_surfaces": palette_surface_results,
        "live_prompt_promotion_hits": prompt_phrase_hits,
        "violations": violations,
        "ok": not violations,
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/check_provenance_live_surfaces.py",
    }


def write_markdown(payload: dict[str, Any]) -> None:
    lines = [
        "# Provenance Live Surface Check",
        "",
        "## Verdict",
        "",
        f"- OK: {payload['ok']}",
        f"- Violation count: {len(payload['violations'])}",
        "",
        "## Guard Checks",
        "",
    ]
    for name, ok in payload["guard_checks"].items():
        lines.append(f"- {name}: {ok}")
    lines += ["", "## Violations", ""]
    if not payload["violations"]:
        lines.append("- None.")
    else:
        for item in payload["violations"]:
            lines.append(f"- `{item.get('path', item.get('check', 'unknown'))}`: {item['type']}")
    lines += [
        "",
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
    payload = run_check()
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_markdown(payload)
    print(json.dumps({
        "wrote": [str(RESULT_PATH), str(DOC_PATH)],
        "ok": payload["ok"],
        "violations": len(payload["violations"]),
    }, indent=2))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
