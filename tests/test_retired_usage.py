"""CI guard: no live code path imports from `kryptos.kernel.retired`.

Allowed importers live in an explicit allow-list: historical-reproducibility
modules and tests that regression-guard the retired machinery. Anything else
is a regression of the framework internal phase 2 quarantine (2026-04-20).

Complements `tests/test_hardening_surfaces.py::test_retired_palette_constants_only_imported_in_quarantined_modules`
which asserts the corresponding negative invariant (nobody imports retired
symbols from the *old* pre-move paths).

Justify every allow-list addition with a code comment in the importing file.
"""

from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parent.parent

# Files explicitly allowed to import retired constants. Every entry must be
# historical-reproducibility code (regression-guards the retired math, or
# an archived experiment kept live for audit) with an in-file comment
# explaining the dependency.
_ALLOW_LIST: frozenset[str] = frozenset(
    {
        # Live kernel code that anchors the retired machinery:
        "src/kryptos/kernel/constraints/stego.py",
        "src/kryptos/kernel/scoring/compliance.py",
        # Retired internalscorer (module docstring: "RETIRED 2026-04-14"):
        "<internal>/polybius_scorer.py",
        # Tests that regression-guard the retired math / palette claims:
        "tests/test_a1_palette_audit.py",
        "tests/test_compliance.py",
        "tests/test_constants.py",
        "tests/test_coupling.py",
        "tests/test_polybius_scorer.py",
        "tests/test_position_mapping.py",
        "tests/test_stego.py",
        "tests/test_stego_solve.py",
    }
)


def _live_python_files():
    """Yield (path, relative_posix_path) pairs for every live .py file.

    Skips: the retired namespace itself, the internal`_archive/` and any
    scripts under `scripts/` (archived experiments live there and are
    outside the Phase 2 live-code perimeter; re-running one is expected to
    fail loudly).
    """
    for p in (_ROOT / "src").rglob("*.py"):
        rel = p.relative_to(_ROOT).as_posix()
        if "retired" in rel:
            continue
        yield p, rel
    for p in (_ROOT / "internal").rglob("*.py"):
        rel = p.relative_to(_ROOT).as_posix()
        if "_archive" in rel:
            continue
        yield p, rel
    for p in (_ROOT / "tests").rglob("*.py"):
        rel = p.relative_to(_ROOT).as_posix()
        yield p, rel


def _imports_retired(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith("kryptos.kernel.retired"):
                return True
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("kryptos.kernel.retired"):
                    return True
    return False


def test_no_live_imports_of_retired_outside_allow_list():
    violators: list[str] = []
    for path, rel in _live_python_files():
        if rel in _ALLOW_LIST:
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        if _imports_retired(tree):
            violators.append(rel)

    assert not violators, (
        "Live files importing from kryptos.kernel.retired outside the "
        f"allow-list: {violators}. "
        "If this import is historical-reproducibility only, add the path "
        "to _ALLOW_LIST in this test with a code comment in the importing "
        "file justifying the dependency. Otherwise, remove the import."
    )


def test_allow_list_entries_exist():
    """Every allow-list entry must point to a real file."""
    missing = [rel for rel in _ALLOW_LIST if not (_ROOT / rel).exists()]
    assert not missing, (
        f"Allow-list entries for nonexistent files: {missing}. "
        "Remove stale allow-list entries when files are deleted or renamed."
    )


def test_allow_list_entries_actually_import_retired():
    """Every allow-list entry must actually import from the retired
    namespace. Stale allow-list entries are technical debt.
    """
    unused = []
    for rel in _ALLOW_LIST:
        path = _ROOT / rel
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        if not _imports_retired(tree):
            unused.append(rel)
    assert not unused, (
        f"Allow-list entries that no longer import retired: {unused}. "
        "Remove them from _ALLOW_LIST so the guard stays tight."
    )
