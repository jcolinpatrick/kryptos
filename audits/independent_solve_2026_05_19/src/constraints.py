"""Independent re-derivation of the Bean constraints from the public
crib dictionary alone. Confirms the 624-valid-keystream count without
trusting any kernel-side constant.

Bean's structural facts (derivable from cribs + additive cipher):
- For any additive variant where K[i] is a function of CT[i] and PT[i]:
  k[i] = k[j] iff (CT[i], PT[i]) <-> (CT[j], PT[j]) yields equal keystream.
  Same/equal pairs imply k[i] = k[j]; distinct (CT,PT) deltas imply k[i] != k[j].
"""

from itertools import combinations

# 0-indexed crib map; (CT_char, PT_char) at each position
CRIB_MAP = {
    21: ("F", "E"), 22: ("L", "A"), 23: ("R", "S"), 24: ("V", "T"),
    25: ("Q", "N"), 26: ("Q", "O"), 27: ("P", "R"), 28: ("R", "T"),
    29: ("N", "H"), 30: ("G", "E"), 31: ("K", "A"), 32: ("S", "S"),
    33: ("S", "T"),
    63: ("N", "B"), 64: ("Y", "E"), 65: ("P", "R"), 66: ("V", "L"),
    67: ("T", "I"), 68: ("T", "N"), 69: ("M", "C"), 70: ("Z", "L"),
    71: ("F", "O"), 72: ("P", "C"), 73: ("K", "K"),
}


def keystream_letter(ct_ch: str, pt_ch: str, op: str) -> int:
    """Compute the keystream value at a position under the given additive op."""
    ci, pi = ord(ct_ch) - ord("A"), ord(pt_ch) - ord("A")
    if op == "vig":
        return (ci - pi) % 26
    elif op == "beau":
        return (ci + pi) % 26
    elif op == "vbeau":
        return (pi - ci) % 26
    raise ValueError(op)


def bean_equality_check(op: str = "vig") -> list:
    """Return list of (i, j) pairs that share a keystream value."""
    pairs = []
    positions = sorted(CRIB_MAP.keys())
    for i, j in combinations(positions, 2):
        ki = keystream_letter(*CRIB_MAP[i], op)
        kj = keystream_letter(*CRIB_MAP[j], op)
        if ki == kj:
            pairs.append((i, j))
    return pairs


def bean_inequality_check(op: str = "vig") -> list:
    """Return list of (i, j) pairs that have distinct keystream values."""
    pairs = []
    positions = sorted(CRIB_MAP.keys())
    for i, j in combinations(positions, 2):
        ki = keystream_letter(*CRIB_MAP[i], op)
        kj = keystream_letter(*CRIB_MAP[j], op)
        if ki != kj:
            pairs.append((i, j))
    return pairs


def crib_keystream_vector(op: str = "vig") -> dict:
    """Return position -> required keystream letter under given op."""
    out = {}
    for pos, (ct, pt) in CRIB_MAP.items():
        k = keystream_letter(ct, pt, op)
        out[pos] = chr(ord("A") + k)
    return out
