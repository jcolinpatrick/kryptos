"""Guard: the Lean formalisation in formal/k4_parity must use the kernel's CT and cribs.

kernel/constants.py is the single source of truth for CT and cribs. Lean cannot import it,
so formal/k4_parity/K4Parity/Data.lean carries literals; this test fails if they drift.
Lean positions are 1-based, the kernel's are 0-based.
"""
import re
from pathlib import Path

from kryptos.kernel.constants import CRIB_DICT, CT

LEAN_DATA = Path(__file__).resolve().parents[1] / "formal" / "k4_parity" / "K4Parity" / "Data.lean"


def _lean_text() -> str:
    return LEAN_DATA.read_text(encoding="utf-8")


def test_lean_ct_matches_kernel() -> None:
    m = re.search(r'def ctStr : String :=\s*"([A-Z]+)"', _lean_text())
    assert m is not None, "ctStr literal not found in Data.lean"
    assert m.group(1) == CT


def test_lean_cribs_match_kernel() -> None:
    blocks = re.findall(r'\("([A-Z]+)"\.toList\.zipIdx (\d+)\)', _lean_text())
    assert len(blocks) == 2, blocks
    lean_cribs = {}
    for word, start in blocks:
        for j, ch in enumerate(word):
            lean_cribs[int(start) - 1 + j] = ch
    assert lean_cribs == dict(CRIB_DICT)
