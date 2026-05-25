"""Lock in that every CriticDecision dispatch site either explicitly
handles REJECT_EMPIRICALLY_DEAD or has a default branch.

This is a grep-style audit test. It does not load every caller; it
asserts the catalog of files we audited at landing time is exactly
the catalog we have today. If a new caller appears, this test breaks
and the auditor must extend the catalog (and audit the new caller)."""
from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Audited at Phase 1 landing time (2026-05-16). Each entry: (relative_path, status).
# status:
#   "handles_explicitly" -- the file produces or handles every variant
#   "has_default_branch" -- the file dispatches on CriticDecision but has
#                           an else/_ branch that catches the new variant
#   "value_check_only"   -- the file only compares against specific values
#                           (e.g. == APPROVE); a new variant falls through
#                           correctly with no change needed
#   "import_only"        -- the file imports CriticDecision but does not
#                           dispatch on its value (e.g. only constructs
#                           verdicts or threads them through unchanged)
AUDITED_DISPATCH_SITES: dict[str, str] = {
    "kryptosbot/critic.py": "handles_explicitly",
    "kryptosbot/controller.py": "value_check_only",
    "kryptosbot/research_tools.py": "import_only",
    "kryptosbot/theory_ledger.py": "import_only",
    # PR 1 (2026-05-17): coverage_audit stores decision as a string
    # (CriticDecision.value) and compares only against the literal
    # "approve" sentinel inside _evaluate_obligation. Any new
    # CriticDecision variant falls through to the "rejected" side of
    # the comparison — the safe default. No CriticDecision import; only
    # a comment in the EmittedSpecRecord schema docstring.
    "kryptosbot/coverage_audit.py": "value_check_only",
}


def test_audited_catalog_matches_current_grep():
    """If grep finds a CriticDecision use in a file not in
    AUDITED_DISPATCH_SITES, the audit must be extended."""
    result = subprocess.run(
        [
            "grep", "-rln", "CriticDecision",
            str(REPO / "kryptosbot"),
            str(REPO / "src"),
            "--include=*.py",
        ],
        capture_output=True, text=True,
    )
    found = set()
    for line in result.stdout.splitlines():
        rel = Path(line).resolve().relative_to(REPO).as_posix()
        if "/tests/" in rel or "/copy/" in rel or "__pycache__" in rel:
            continue
        if rel.endswith("kryptosbot/models.py"):
            continue  # the definition site
        found.add(rel)
    audited = set(AUDITED_DISPATCH_SITES.keys())
    missing = found - audited
    assert not missing, (
        f"New CriticDecision dispatch site(s) not audited: {sorted(missing)}. "
        f"Add to AUDITED_DISPATCH_SITES with appropriate handling note."
    )
