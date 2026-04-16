from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RETIRED_SYMBOLS = {"NULL_PALETTE", "CONSENSUS_NULL_POSITIONS"}


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
    hits = _direct_retired_imports()
    allowed = {
        (
            "src/kryptos/kernel/constraints/stego.py",
            "kryptos.kernel.constants",
        ),
        (
            "<internal>/polybius_scorer.py",
            "kryptos.kernel.constants",
        ),
    }
    observed = {(path, module) for path, module, _ in hits}
    assert observed == allowed, (
        "Retired palette/null-mask constants leaked into unexpected live import paths: "
        f"{sorted(observed - allowed)}"
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
