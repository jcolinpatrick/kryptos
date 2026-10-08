""

from __future__ import annotations

STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def keyed_alphabet(keyword: str, base: str = STD_ALPHABET) -> str:
    ""

    base_set = set(base)
    seen: list[str] = []
    for char in keyword + base:
        upper = char.upper()
        if upper in base_set and upper not in seen:
            seen.append(upper)
    return "".join(seen)


KRYPTOS_ALPHABET = keyed_alphabet("KRYPTOS")
