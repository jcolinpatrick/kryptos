"""Polybius-family ciphers: bifid, trifid, and ADFGVX.

These fractionation ciphers convert letters to coordinates, operate on
the coordinates, then convert back. They produce fundamentally different
ciphertext statistics than simple polyalphabetic ciphers.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from kryptos.kernel.constants import MOD


def make_polybius_5x5(keyword: str = "", merge: str = "IJ") -> List[str]:
    """Create a 5x5 Polybius square from a keyword.

    By default merges I and J. The merge parameter specifies which two
    letters share a cell: "IJ" (default), "CK", or "VW".

    Returns a flat list of 25 characters representing the 5x5 grid
    (row-major order).
    """
    # Determine which letter to drop
    drop_map = {"IJ": "J", "CK": "K", "VW": "W"}
    drop = drop_map.get(merge, "J")
    replace_map = {"IJ": ("J", "I"), "CK": ("K", "C"), "VW": ("W", "V")}
    replace_from, replace_to = replace_map.get(merge, ("J", "I"))

    base = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    seen: set[str] = set()
    grid: list[str] = []

    for ch in keyword.upper() + base:
        ch = ch if ch != replace_from else replace_to
        if ch not in seen and ch in base and ch != drop:
            seen.add(ch)
            grid.append(ch)

    assert len(grid) == 25, f"Polybius grid has {len(grid)} cells, expected 25"
    return grid


def polybius_encode(text: str, grid: List[str]) -> List[Tuple[int, int]]:
    """Encode text to (row, col) pairs using a 5x5 Polybius square."""
    lookup = {ch: (i // 5, i % 5) for i, ch in enumerate(grid)}
    # Handle merged letters
    if "J" not in lookup and "I" in lookup:
        lookup["J"] = lookup["I"]
    if "K" not in lookup and "C" in lookup:
        lookup["K"] = lookup["C"]

    result: list[tuple[int, int]] = []
    for ch in text.upper():
        if ch in lookup:
            result.append(lookup[ch])
    return result


def polybius_decode(coords: List[Tuple[int, int]], grid: List[str]) -> str:
    """Decode (row, col) pairs back to text using a 5x5 Polybius square."""
    return "".join(grid[r * 5 + c] for r, c in coords if 0 <= r < 5 and 0 <= c < 5)


def bifid_encrypt(plaintext: str, grid: List[str], period: int = 0) -> str:
    """Bifid cipher encryption.

    If period == 0, uses full-length period (classical bifid).
    """
    coords = polybius_encode(plaintext, grid)
    if not coords:
        return ""

    if period == 0:
        period = len(coords)

    result: list[str] = []
    for start in range(0, len(coords), period):
        block = coords[start : start + period]
        rows = [r for r, _ in block]
        col_vals = [c for _, c in block]
        combined = rows + col_vals
        new_coords = [(combined[i], combined[i + len(block)]) for i in range(len(block))]
        result.append(polybius_decode(new_coords, grid))

    return "".join(result)


def bifid_decrypt(ciphertext: str, grid: List[str], period: int = 0) -> str:
    """Bifid cipher decryption."""
    coords = polybius_encode(ciphertext, grid)
    if not coords:
        return ""

    if period == 0:
        period = len(coords)

    result: list[str] = []
    for start in range(0, len(coords), period):
        block = coords[start : start + period]
        rows = [r for r, _ in block]
        col_vals = [c for _, c in block]
        combined = rows + col_vals
        half = len(block)
        orig_rows = combined[:half]
        orig_cols = combined[half:]
        orig_coords = list(zip(orig_rows, orig_cols))
        result.append(polybius_decode(orig_coords, grid))

    return "".join(result)
