from __future__ import annotations

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RETIRED_SYMBOLS = {"NULL_PALETTE", "CONSENSUS_NULL_POSITIONS"}
RETIRED_CONSTRUCT_RE = re.compile(
    r"CONSENSUS_NULL_POSITIONS|NULL_PALETTE|consensus null|null palette",
    re.IGNORECASE,
)


def _direct_retired_imports() -> list[tuple[str, str, tuple[str, ...]]]:
    hits: list[tuple[str, str, tuple[str, ...]]] = []
    for base in (ROOT / "src", ROOT / "internal"):
        for path in base.rglob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.ImportFrom):
                    continue
                if node.module not in {"kryptos.kernel.constants", "<internal>"}:
                    continue
                names = tuple(alias.name for alias in node.names)
                if RETIRED_SYMBOLS & set(names):
                    hits.append((str(path.relative_to(ROOT)), node.module, names))
    return hits


def test_retired_palette_constants_only_imported_in_quarantined_modules():
    """No live file may import retired symbols from kryptos.kernel.constants
    or <internal>.

    Retired constants moved to kryptos.kernel.retired in internal framework
    Phase 2 (2026-04-20). Legitimate historical-reproducibility importers go
    through the retired namespace and are enumerated in
    tests/test_retired_usage.py's allow-list; any attempt to import them from
    the old path is a regression (the symbols no longer exist there, so the
    import would fail at runtime, but this check catches it at collection
    time instead).
    """
    hits = _direct_retired_imports()
    assert not hits, (
        "Retired symbols still imported from the pre-Phase-2 paths "
        "(kryptos.kernel.constants / <internal>). "
        f"Offending files: {[h[0] for h in hits]}. "
        "Switch the imports to `from kryptos.kernel.retired import ...` "
        "and add the file to the allow-list in tests/test_retired_usage.py."
    )


def test_active_nullmask_results_do_not_overclaim_global_elimination():
    targets = [
        ROOT / "results" / "h_624_73_nullmask" / "result.md",
        ROOT / "results" / "h_624_73_nullmask" / "repaired_run.md",
    ]
    forbidden = (
        "rules out k4 globally",
        "global elimination of k4",
        "proves k4",
        "must be the solution",
    )
    required = (
        "conditional",
        "does not eliminate k4 globally",
        "assumption bundle",
    )
    for path in targets:
        text = path.read_text().lower()
        for needle in forbidden:
            assert needle not in text, f"{path} contains forbidden phrase {needle!r}"
        for needle in required:
            assert needle in text, f"{path} missing required caution phrase {needle!r}"


def test_nondeprecated_f_campaigns_with_retired_constructs_are_quarantined():
    targets = []
    for path in (ROOT / "scripts" / "campaigns").glob("f_*.py"):
        text = path.read_text(encoding="utf-8")
        if not RETIRED_CONSTRUCT_RE.search(text):
            continue
        if "DEPRECATED:" in text:
            continue
        targets.append(path)

    assert targets, "expected at least one quarantined retired-construct f_* campaign"

    for path in targets:
        text = path.read_text(encoding="utf-8")
        assert "--allow-retired-construct" in text, f"{path} missing explicit opt-in"
        assert (
            "historical artifact" in text or "historical / reproducibility artifact" in text
        ), f"{path} missing historical quarantine warning"
