"""Independent scoring. Crib match + holdout-aware variants. No kernel imports."""

from .alphabets import AZ


CRIBS = [
    (21, "EASTNORTHEAST"),  # 0-indexed; prompt's 1-indexed 22-34
    (63, "BERLINCLOCK"),    # 0-indexed; prompt's 1-indexed 64-74
]


def crib_score(plaintext: str, withheld_crib_index: int = -1) -> tuple:
    """Return (hits, total, per-position-bool list).

    `withheld_crib_index`: -1 = score against both cribs (the default).
    0 = score against ONLY the BERLIN/CLOCK crib (EAST/NORTHEAST withheld).
    1 = score against ONLY the EAST/NORTHEAST crib (BERLIN/CLOCK withheld).
    """
    if len(plaintext) < 74:
        raise ValueError(f"plaintext too short: {len(plaintext)} < 74")
    hits = 0
    total = 0
    matches = []
    for ci, (start, crib) in enumerate(CRIBS):
        if ci == withheld_crib_index:
            continue
        for offset, ch in enumerate(crib):
            pos = start + offset
            ok = plaintext[pos].upper() == ch
            matches.append((pos, ch, plaintext[pos], ok))
            total += 1
            if ok:
                hits += 1
    return hits, total, matches


def holdout_predictions(plaintext: str, withheld_crib_index: int) -> dict:
    """Read what the method predicts at the withheld crib positions.

    Returns predicted/expected for the *withheld* crib so a holdout test
    can confirm whether the method recovered them without using them.
    """
    if withheld_crib_index not in (0, 1):
        raise ValueError("withheld_crib_index must be 0 (EAST/NORTHEAST) or 1 (BERLIN/CLOCK)")
    start, crib = CRIBS[withheld_crib_index]
    hits = sum(1 for o, ch in enumerate(crib) if plaintext[start + o].upper() == ch)
    return {
        "withheld": "EASTNORTHEAST" if withheld_crib_index == 0 else "BERLINCLOCK",
        "start": start,
        "expected": crib,
        "predicted": plaintext[start:start + len(crib)],
        "hits": hits,
        "total": len(crib),
        "passes": hits == len(crib),
    }
