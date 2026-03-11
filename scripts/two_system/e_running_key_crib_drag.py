#!/usr/bin/env python3
"""
Running-key crib-drag on Carter book texts.

Strategy: At each of the 24 crib positions we know CT[i] and PT[i],
so we can derive the REQUIRED running-key character for each cipher variant.
Then we slide a 97-char window across the entire book and check how many
of the 24 required key characters match the book text at those offsets.

A perfect match (24/24) means the passage is the running key.
Even partial matches (18+/24) would be extraordinary signal.

This is computationally trivial: O(book_length × 24) per variant.

Also tests with transposition: for each promising column order (width 7-14),
undo transposition first, then crib-drag on the intermediate text.
"""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, MOD


def derive_required_key(variant: str) -> dict[int, int]:
    """Derive what the running-key character must be at each crib position.

    Returns {position: required_key_value} for each of 24 crib positions.
    """
    required = {}
    for pos, pt_ch in CRIB_DICT.items():
        c = ord(CT[pos]) - 65
        p = ord(pt_ch) - 65
        if variant == "vigenere":
            k = (c - p) % MOD
        elif variant == "beaufort":
            k = (c + p) % MOD
        elif variant == "var_beaufort":
            k = (p - c) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        required[pos] = k
    return required


def sanitize(text: str) -> str:
    """Strip to uppercase alpha only."""
    return re.sub(r"[^A-Z]", "", text.upper())


def crib_drag(book_alpha: str, required_key: dict[int, int], ct_len: int = 97) -> list[tuple[int, int, str]]:
    """Slide a ct_len-char window across book_alpha, count crib matches.

    Returns list of (offset, match_count, matched_positions_str) sorted by match_count desc.
    Only returns results with match_count >= threshold.
    """
    n = len(book_alpha)
    if n < ct_len:
        return []

    results = []
    positions = sorted(required_key.keys())

    for offset in range(n - ct_len + 1):
        matches = 0
        for pos in positions:
            book_idx = offset + pos
            book_val = ord(book_alpha[book_idx]) - 65
            if book_val == required_key[pos]:
                matches += 1

        if matches >= 6:  # Only store if above random expectation (~1)
            matched = [pos for pos in positions if ord(book_alpha[offset + pos]) - 65 == required_key[pos]]
            results.append((offset, matches, str(matched)))

    results.sort(key=lambda x: x[1], reverse=True)
    return results


def crib_drag_on_transposed(book_alpha: str, required_key: dict[int, int],
                             perm: list[int], ct_len: int = 97) -> list[tuple[int, int, str]]:
    """Crib-drag after undoing a transposition.

    If encryption is PT → transposition → running-key-sub → CT,
    then to undo: CT → undo-sub(with book key) → undo-transposition → PT.
    The running key operates on the TRANSPOSED text, so the key positions
    shift according to the transposition.

    Alternatively: the crib positions in PT map to different positions
    in the intermediate (transposed) text. We need to find where each
    crib position lands after transposition.
    """
    # inv_perm: if transposed[i] = PT[perm[i]], then PT[j] = transposed[inv_perm[j]]
    # Crib gives us PT[pos] for crib positions.
    # transposed[i] = PT[perm[i]], so PT[pos] = transposed[inv_perm[pos]]
    # The running key operates on transposed: CT[i] = sub(transposed[i], key[i])
    # So: transposed[i] = unsub(CT[i], key[i])
    # And: PT[pos] = transposed[inv_perm[pos]] = unsub(CT[inv_perm[pos]], key[inv_perm[pos]])
    # Therefore the key value at position inv_perm[pos] must satisfy:
    # CRIB_DICT[pos] = unsub(CT[inv_perm[pos]], key[inv_perm[pos]])

    inv_perm = [0] * len(perm)
    for i, p in enumerate(perm):
        inv_perm[p] = i

    # Remap required key: for each crib pos, the key constraint is at inv_perm[pos]
    remapped_key: dict[int, int] = {}
    for pos, pt_ch in CRIB_DICT.items():
        mapped_pos = inv_perm[pos]
        c = ord(CT[mapped_pos]) - 65
        p = ord(pt_ch) - 65
        # Re-derive for vigenere (most common)
        k = (c - p) % MOD
        remapped_key[mapped_pos] = k

    return crib_drag(book_alpha, remapped_key, ct_len)


def columnar_perm(width: int, col_order: list[int], length: int = 97) -> list[int]:
    """Build columnar transposition permutation."""
    from collections import defaultdict
    cols: dict[int, list[int]] = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm: list[int] = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        perm.extend(cols[col_idx])
    return perm


def keyword_to_order(keyword: str, width: int) -> list[int] | None:
    """Convert keyword to column order."""
    kw = keyword[:width].upper()
    if len(kw) < width:
        return None
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def main():
    book_files = [
        Path(__file__).resolve().parent.parent.parent / "reference" / "carter_gutenberg.txt",
        Path(__file__).resolve().parent.parent.parent / "reference" / "carter_vol1.txt",
    ]

    # Also check for any other text files in reference/
    ref_dir = Path(__file__).resolve().parent.parent.parent / "reference"
    for f in sorted(ref_dir.glob("*.txt")):
        if f not in book_files:
            book_files.append(f)

    variants = ["vigenere", "beaufort", "var_beaufort"]

    print("=" * 70)
    print("  Running-Key Crib-Drag on Reference Texts")
    print("=" * 70)
    print(f"  CT length: {CT_LEN}")
    print(f"  Crib positions: {len(CRIB_DICT)} known PT/CT pairs")
    print(f"  Expected random matches per window: {24/26:.1f}")
    print(f"  Signal threshold: 10+ matches (p < 1e-6)")
    print()

    # ── Phase 1: Direct crib-drag (no transposition) ──
    print("Phase 1: Direct crib-drag (no transposition)")
    print("-" * 50)

    for variant in variants:
        required = derive_required_key(variant)

        # Show what we're looking for
        key_chars = "".join(chr(required[pos] + 65) for pos in sorted(required.keys()))
        print(f"\n  Variant: {variant}")
        print(f"  Required key at crib positions: {key_chars}")

        for book_file in book_files:
            if not book_file.exists():
                continue
            text = book_file.read_text(errors="ignore")
            book_alpha = sanitize(text)
            print(f"  Book: {book_file.name} ({len(book_alpha):,} alpha chars)")

            start = time.monotonic()
            results = crib_drag(book_alpha, required, CT_LEN)
            elapsed = time.monotonic() - start

            if results:
                best_match = results[0][1]
                print(f"    Best match: {best_match}/24 ({elapsed:.2f}s, {len(results)} windows ≥6)")
                for offset, count, matched in results[:10]:
                    # Show surrounding context
                    context = book_alpha[offset:offset + CT_LEN]
                    # Find original text position
                    print(f"    offset={offset:>7d} matches={count:>2d}/24 key_window={context[:40]}...")
            else:
                print(f"    No windows with ≥6 matches ({elapsed:.2f}s)")

    # ── Phase 2: Crib-drag with transposition ──
    print("\n\nPhase 2: Crib-drag with transposition (keyword-derived column orders)")
    print("-" * 50)

    keywords = [
        "KRYPTOS", "SANBORN", "SCHEIDT", "BERLIN", "URANIA", "KOMPASS",
        "DEFECTOR", "PARALLAX", "COLOPHON", "ABSCISSA", "PALIMPSEST",
        "ENIGMA", "SHADOW", "COMPASS", "LODESTONE", "SPHINX", "CARTER",
        "EGYPT", "CLOCK", "POINT", "HIDDEN", "SECRET", "CIPHER",
        "TUTANKHAMUN", "HIEROGLYPH",
    ]

    best_overall = 0
    best_overall_info = ""

    for book_file in book_files:
        if not book_file.exists():
            continue
        text = book_file.read_text(errors="ignore")
        book_alpha = sanitize(text)
        if len(book_alpha) < CT_LEN:
            continue

        print(f"\n  Book: {book_file.name}")

        for width in range(4, 15):
            for kw in keywords:
                order = keyword_to_order(kw, width)
                if order is None:
                    continue
                perm = columnar_perm(width, order, CT_LEN)

                # Only test vigenere for transposition (most likely)
                required = derive_required_key("vigenere")

                # Remap through transposition
                inv_perm = [0] * len(perm)
                for i, p in enumerate(perm):
                    inv_perm[p] = i

                remapped: dict[int, int] = {}
                for pos, pt_ch in CRIB_DICT.items():
                    mapped_pos = inv_perm[pos]
                    c = ord(CT[mapped_pos]) - 65
                    p = ord(pt_ch) - 65
                    k = (c - p) % MOD
                    remapped[mapped_pos] = k

                results = crib_drag(book_alpha, remapped, CT_LEN)

                if results and results[0][1] > 6:
                    count = results[0][1]
                    offset = results[0][0]
                    if count > best_overall:
                        best_overall = count
                        best_overall_info = (f"w={width} kw={kw} book={book_file.name} "
                                            f"offset={offset} matches={count}/24")
                    if count >= 8:
                        print(f"    w={width:2d} kw={kw:15s} best={count:2d}/24 "
                              f"offset={offset:>7d}")

    print(f"\n\nBest overall (with transposition): {best_overall_info or 'nothing above 6'}")

    # ── Phase 3: Exhaustive width-9 with identity (no keyword) ──
    # Try ALL offsets with just the direct required key on the largest book
    print("\n\nPhase 3: Distribution of match counts (direct, no transposition)")
    print("-" * 50)
    for variant in variants:
        required = derive_required_key(variant)
        for book_file in book_files[:2]:  # Just the two Carter books
            if not book_file.exists():
                continue
            text = book_file.read_text(errors="ignore")
            book_alpha = sanitize(text)

            # Count distribution of matches
            n = len(book_alpha)
            dist = [0] * 25
            max_count = 0
            max_offset = 0
            for offset in range(n - CT_LEN + 1):
                matches = 0
                for pos in sorted(required.keys()):
                    if ord(book_alpha[offset + pos]) - 65 == required[pos]:
                        matches += 1
                dist[matches] += 1
                if matches > max_count:
                    max_count = matches
                    max_offset = offset

            print(f"\n  {variant} / {book_file.name}:")
            print(f"    Max matches: {max_count}/24 at offset {max_offset}")
            # Show distribution for counts >= 3
            for i in range(3, 25):
                if dist[i] > 0:
                    print(f"    {i:2d} matches: {dist[i]:>6d} windows")

    print("\n" + "=" * 70)
    print("  Done.")
    print("=" * 70)


if __name__ == "__main__":
    main()
