"""Independent statistics on the K4 ciphertext. Stdlib only."""

from collections import Counter
from .alphabets import AZ


def frequency(text: str) -> dict:
    text = "".join(c for c in text.upper() if c.isalpha())
    return dict(Counter(text))


def index_of_coincidence(text: str) -> float:
    text = "".join(c for c in text.upper() if c.isalpha())
    n = len(text)
    if n < 2:
        return 0.0
    f = Counter(text)
    return sum(c * (c - 1) for c in f.values()) / (n * (n - 1))


def repeated_ngrams(text: str, n: int = 3) -> dict:
    text = "".join(c for c in text.upper() if c.isalpha())
    occurrences = {}
    for i in range(len(text) - n + 1):
        gram = text[i:i + n]
        occurrences.setdefault(gram, []).append(i)
    return {g: positions for g, positions in occurrences.items() if len(positions) >= 2}


def kasiski_gaps(text: str, n: int = 3) -> list:
    repeats = repeated_ngrams(text, n)
    gaps = []
    for gram, positions in repeats.items():
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                gaps.append((gram, positions[j] - positions[i]))
    return gaps


def autocorrelation(text: str, max_shift: int = 30) -> list:
    text = "".join(c for c in text.upper() if c.isalpha())
    n = len(text)
    return [(s, sum(1 for i in range(n - s) if text[i] == text[i + s])) for s in range(1, max_shift + 1)]


def keystream_deltas_at_crib(ct: str, crib_start: int, crib: str, alpha: str, operation: str) -> list:
    """At each crib position, compute the keystream letter required if the
    cipher is the given (alpha, operation) pair.

    operation: 'vig'  -> K = idx(CT) - idx(PT)  (mod 26)
               'beau' -> K = idx(CT) + idx(PT)  (mod 26) for Beaufort reciprocal
               'vbeau'-> K = idx(PT) - idx(CT)  (mod 26) for Variant Beaufort
    """
    out = []
    for o, p_ch in enumerate(crib):
        i = crib_start + o
        c_ch = ct[i]
        ci, pi = alpha.index(c_ch), alpha.index(p_ch)
        if operation == "vig":
            k = (ci - pi) % 26
        elif operation == "beau":
            k = (ci + pi) % 26
        elif operation == "vbeau":
            k = (pi - ci) % 26
        else:
            raise ValueError(operation)
        out.append((i, p_ch, c_ch, alpha[k]))
    return out
