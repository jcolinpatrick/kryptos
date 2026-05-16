"""W-anchored swap spot check.

For each candidate transposition variant, compute the implied keystream at the
known crib positions under Vigenere / Beaufort / Variant Beaufort. If any
variant + cipher combination produces a recognizable English keystream
fragment (keyword roots, common bigrams, vowel-heavy structure), it's a
candidate worth a real sweep. Otherwise the variant is falsified for
single-layer additive substitution.

Variants tested:
  NONE                 — no swap (baseline; same as standard K4 attack)
  SWAP_FULL_REV        — full reversal (anchored at central W, pos 48)
  SWAP_SEG_ORDER       — segment-order reversal (W's mark segments, order flipped)
  SWAP_SEG_INTERNAL    — each W-segment reversed internally, order kept
  SWAP_REFL_p          — reflection around position p (for each W); positions
                         where 2p-i is out of range are left in place
"""
import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, CRIB_WORDS

W_POSITIONS = [i for i, c in enumerate(CT) if c == "W"]
assert W_POSITIONS == [20, 36, 48, 58, 74]

CRIB_REGIONS = [
    ("EAST",      21, 24),
    ("NORTHEAST", 25, 33),
    ("BERLIN",    63, 68),
    ("CLOCK",     69, 73),
]


def chr_to_int(c: str) -> int:
    return ord(c) - ord("A")


def int_to_chr(n: int) -> str:
    return chr(n % 26 + ord("A"))


def swap_none(ct: str) -> str:
    return ct


def swap_full_reverse(ct: str) -> str:
    return ct[::-1]


def _split_by_w(ct: str, w_positions: list[int]) -> list[str]:
    segments = []
    last = 0
    for p in w_positions:
        segments.append(ct[last:p])
        last = p
    segments.append(ct[last:])
    return segments


def swap_segment_order_reverse(ct: str) -> str:
    segs = _split_by_w(ct, W_POSITIONS)
    return "".join(reversed(segs))


def swap_segment_internal_reverse(ct: str) -> str:
    segs = _split_by_w(ct, W_POSITIONS)
    return "".join(s[::-1] for s in segs)


def swap_reflection_around(ct: str, pivot: int) -> str:
    n = len(ct)
    out = list(ct)
    for i in range(n):
        j = 2 * pivot - i
        if 0 <= j < n:
            out[i] = ct[j]
    return "".join(out)


def implied_keystream(ct_swapped: str, cipher: str, region_start: int, region_end: int, pt_word: str) -> str:
    """K = f(CT, PT) at each crib position. cipher in {vig, beau, varbeau}."""
    ks = []
    for offset, pt_c in enumerate(pt_word):
        pos = region_start + offset
        ct_v = chr_to_int(ct_swapped[pos])
        pt_v = chr_to_int(pt_c)
        if cipher == "vig":
            k = (ct_v - pt_v) % 26
        elif cipher == "beau":
            k = (ct_v + pt_v) % 26
        elif cipher == "varbeau":
            k = (pt_v - ct_v) % 26
        else:
            raise ValueError(cipher)
        ks.append(int_to_chr(k))
    return "".join(ks)


# --- Light scoring: keyword fragments and high-frequency letter density ---

ETAOIN = set("ETAOINSHR")
KEYWORD_ROOTS = [
    "KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLIN", "CLOCK", "SCHEIDT",
    "SANBORN", "LANGLEY", "VIRTUAL", "ECLIPSE", "SHADOW", "INVISIBLE",
    "UNDERGROUND", "WHISPERED", "BETWEEN", "SLOWLY", "TRANSMITTED",
    "AGENCY", "INTELLIGENCE", "CIPHER", "EAST", "NORTH", "WEST", "SOUTH",
]


def english_density(ks: str) -> float:
    if not ks:
        return 0.0
    return sum(1 for c in ks if c in ETAOIN) / len(ks)


def keyword_overlaps(ks: str, min_len: int = 3) -> list[str]:
    """Return any substring of length >= min_len shared with a known keyword."""
    hits = []
    for root in KEYWORD_ROOTS:
        for L in range(min_len, len(ks) + 1):
            for i in range(len(ks) - L + 1):
                frag = ks[i : i + L]
                if frag in root:
                    hits.append(f"{frag}∈{root}")
    return sorted(set(hits))


def variant_summary(name: str, ct_swapped: str, ciphers: list[str]) -> None:
    print(f"\n{'=' * 78}")
    print(f"VARIANT: {name}")
    print(f"  carved-region [0:30] : {ct_swapped[0:30]}")
    print(f"  carved-region [60:97]: {ct_swapped[60:97]}")
    # Show the literal CT letters at each crib region
    print(f"  CT at crib regions:")
    for cname, s, e in CRIB_REGIONS:
        print(f"    {cname:10s} [{s:2d}..{e:2d}]: {ct_swapped[s:e+1]}")
    print()

    # Header
    h = f"  {'CIPHER':9s}"
    for cname, _, _ in CRIB_REGIONS:
        h += f"  {cname:>10s}"
    h += f"  {'ETAOIN%':>8s}  HITS"
    print(h)
    print("  " + "-" * (len(h) - 2))

    for cipher in ciphers:
        ks_all = ""
        row_cells = []
        for cname, s, e in CRIB_REGIONS:
            pt_word = "".join(CRIB_DICT[p] for p in range(s, e + 1))
            ks = implied_keystream(ct_swapped, cipher, s, e, pt_word)
            row_cells.append(f"{ks:>10s}")
            ks_all += ks
        density = english_density(ks_all)
        hits = keyword_overlaps(ks_all)
        hits_str = ", ".join(hits[:6]) + (f" (+{len(hits)-6})" if len(hits) > 6 else "")
        print(f"  {cipher.upper():9s}  " + "  ".join(row_cells) + f"  {density*100:6.1f}%   {hits_str}")


def main():
    print(f"K4 carved : {CT}")
    print(f"length    : {len(CT)}")
    print(f"W positions: {W_POSITIONS}  (5 W's; central W at index 48)")

    ciphers = ["vig", "beau", "varbeau"]

    # Random/noise baseline expectation:
    #   ETAOIN density: 9 letters / 26 = ~34.6%
    #   English text:   ~70%
    print(f"\nNoise baseline: ETAOIN density ~34.6%; English text ~70%.")
    print(f"A real keystream fragment from an English keyword should land >50%.\n")

    variants = [
        ("NONE (baseline)",                    swap_none(CT)),
        ("SWAP_FULL_REV (anchor=W₃ at 48)",    swap_full_reverse(CT)),
        ("SWAP_SEG_ORDER (anchor=W₃ at 48)",   swap_segment_order_reverse(CT)),
        ("SWAP_SEG_INTERNAL",                  swap_segment_internal_reverse(CT)),
    ]
    for w in W_POSITIONS:
        variants.append((f"SWAP_REFL around W at pos {w}",
                         swap_reflection_around(CT, w)))

    for name, swapped in variants:
        variant_summary(name, swapped, ciphers)

    print(f"\n{'=' * 78}")
    print("READING NOTES")
    print(f"{'=' * 78}")
    print("Implied keystream is what the key letters MUST be at crib positions")
    print("for that variant + cipher to decrypt to EAST/NORTHEAST/BERLIN/CLOCK.")
    print("Look for: keyword fragments, English bigrams, vowel-rich structure,")
    print("or repeated letters across the four regions (would indicate a periodic key).")
    print("ETAOIN >= 50% AND >=2 keyword hits in distinct regions = worth a real sweep.")


if __name__ == "__main__":
    main()
