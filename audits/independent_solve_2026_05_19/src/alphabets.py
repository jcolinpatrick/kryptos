"""Independent reference alphabets. Pure stdlib. No kryptos.kernel imports.

AZ  = standard A-Z.
KA  = Kryptos-keyed alphabet, as used by K1/K2 on the carved tableau.
AZR = AZ reversed.
KAR = KA reversed.

`mixed_alphabet(keyword)` produces a keyword-mixed alphabet: deduplicated
keyword letters first, then remaining A-Z in order. Used by all
substitution searches that pull keys from public Kryptos vocabulary.
"""

AZ  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA  = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZR = AZ[::-1]
KAR = KA[::-1]

assert len(AZ) == 26 and len(set(AZ)) == 26
assert len(KA) == 26 and len(set(KA)) == 26, "KA must contain all 26 letters; the 'KA has no J' rumour is wrong"


def index_in(alpha: str, ch: str) -> int:
    """Position of ch within alpha. Raises ValueError on miss."""
    return alpha.index(ch)


def char_at(alpha: str, idx: int) -> str:
    """alpha[idx % 26]; safe for arbitrary integer idx."""
    return alpha[idx % 26]


def mixed_alphabet(keyword: str) -> str:
    """Keyword-mixed alphabet: dedup'd keyword letters + remaining A-Z."""
    keyword = "".join(c for c in keyword.upper() if c.isalpha())
    seen = []
    for ch in keyword:
        if ch not in seen:
            seen.append(ch)
    for ch in AZ:
        if ch not in seen:
            seen.append(ch)
    out = "".join(seen)
    assert len(out) == 26 and len(set(out)) == 26
    return out
