"""The crib-set ladder under test, from released ground truth up to the full
challenge-response reconstruction.

L0 is the only level that is EVIDENCE. Everything above it is HYPOTHESIS, and
any mechanism eliminated at L1+ is eliminated only CONDITIONAL on that
hypothesis being true. Report the level with every claim.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CRIB_DICT  # noqa: E402

OPENING = "YESWONDERFULTHINGS"          # PT[0:18]
FILLER = "XGO"                          # PT[18:21]
BRIDGE_RESET = "RESETTHOSECOORDINATESUSINGTHE"   # PT[34:63], Layout A, 29 chars
BRIDGE_REKEY = "REKEYTHOSECOORDINATESUSINGTHE"   # PT[34:63], Layout A, 29 chars


def _spread(d, start, text):
    for i, ch in enumerate(text):
        d[start + i] = ch
    return d


def _base():
    return dict(CRIB_DICT)


def level(name: str) -> dict[int, str]:
    d = _base()
    if name == "L0_released":
        pass
    elif name == "L1_opening":
        _spread(d, 0, OPENING)
    elif name == "L2_opening_xgo":
        _spread(d, 0, OPENING); _spread(d, 18, FILLER)
    elif name == "L3_layoutB_x34":
        _spread(d, 0, OPENING); _spread(d, 18, FILLER); d[34] = "X"
    elif name == "L4_layoutA_reset":
        _spread(d, 0, OPENING); _spread(d, 18, FILLER); _spread(d, 34, BRIDGE_RESET)
    elif name == "L5_layoutA_rekey":
        _spread(d, 0, OPENING); _spread(d, 18, FILLER); _spread(d, 34, BRIDGE_REKEY)
    else:
        raise ValueError(f"unknown level {name!r}")
    return d


LEVELS = ["L0_released", "L1_opening", "L2_opening_xgo",
          "L3_layoutB_x34", "L4_layoutA_reset", "L5_layoutA_rekey"]

DESCRIPTIONS = {
    "L0_released":      "released cribs only — the only EVIDENCE level",
    "L1_opening":       "+ YESWONDERFULTHINGS at 0-17",
    "L2_opening_xgo":   "+ XGO at 18-20",
    "L3_layoutB_x34":   "+ X separator at 34 (Colin's Layout B)",
    "L4_layoutA_reset": "+ RESET THOSE COORDINATES USING THE at 34-62 (Layout A)",
    "L5_layoutA_rekey": "+ REKEY THOSE COORDINATES USING THE at 34-62 (Layout A)",
}

if __name__ == "__main__":
    for lv in LEVELS:
        d = level(lv)
        row = "".join(d.get(i, ".") for i in range(97))
        print(f"{lv:<18} n={len(d):>3}  {row}")
        print(f"{'':<18}        {DESCRIPTIONS[lv]}")
