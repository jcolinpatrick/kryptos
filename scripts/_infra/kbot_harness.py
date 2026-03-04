"""
Cipher: infrastructure
Family: _infra
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Pre-deployed test harness for KryptosBot agent sessions.

Provides validated scoring, cipher, and permutation functions so agents
don't need to rewrite them every session.

Usage from agent scripts::

    import sys
    sys.path.insert(0, 'scripts')
    from kbot_harness import test_perm, score_text, K4_CARVED, KEYWORDS

All constants are duplicated here for standalone use (no dependency on
kryptos.kernel.constants), but values are identical to the canonical source.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("kbot_harness")

# ── Constants ────────────────────────────────────────────────────────────────

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
K4_LEN = 97

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA",
]

CRIBS = ["EASTNORTHEAST", "BERLINCLOCK"]


# ── Quadgram scoring ─────────────────────────────────────────────────────────

_QUADGRAMS: dict[str, float] | None = None

_QUADGRAM_PATHS = [
    Path("data/english_quadgrams.json"),
    Path("../data/english_quadgrams.json"),
    Path(__file__).resolve().parent.parent / "data" / "english_quadgrams.json",
]


def load_quadgrams() -> dict[str, float]:
    """Load quadgram log-probabilities from ``data/english_quadgrams.json``.

    Raises :exc:`FileNotFoundError` if the quadgram file cannot be found,
    rather than silently returning an empty dict.
    """
    global _QUADGRAMS
    if _QUADGRAMS is not None:
        return _QUADGRAMS
    for p in _QUADGRAM_PATHS:
        if p.exists():
            _QUADGRAMS = json.loads(p.read_text())
            logger.info("Loaded %d quadgrams from %s", len(_QUADGRAMS), p)
            return _QUADGRAMS
    raise FileNotFoundError(
        "Quadgram file not found. Searched: "
        + ", ".join(str(p) for p in _QUADGRAM_PATHS)
        + "\nEnsure data/english_quadgrams.json exists."
    )


def score_text(text: str) -> float:
    """Quadgram log-probability score (total sum).

    Returns the sum of log-probabilities for all quadgrams in *text*.
    Typical 97-char English: ~-400, random: ~-940.
    """
    qg = load_quadgrams()
    s = text.upper()
    return sum(qg.get(s[i : i + 4], -10.0) for i in range(len(s) - 3))


def score_text_per_char(text: str) -> float:
    """Quadgram log-probability score per quadgram.

    Typical English: ~-4.2/char, random: ~-10.0/char.
    """
    s = text.upper()
    n = len(s)
    if n < 4:
        return -10.0
    total = score_text(text)
    return total / (n - 3)


# ── Crib detection ───────────────────────────────────────────────────────────


def has_cribs(text: str) -> list[tuple[str, int]]:
    """Search for crib strings anywhere in *text*.

    Returns list of ``(crib_string, position)`` for each found crib.
    """
    found = []
    upper = text.upper()
    for crib in CRIBS:
        idx = upper.find(crib)
        if idx >= 0:
            found.append((crib, idx))
    return found


# ── Cipher functions ─────────────────────────────────────────────────────────


def vig_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    """Vigenere decryption: ``PT[i] = (CT[i] - key[i]) mod 26``."""
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % len(key)])
        result.append(alpha[(ci - ki) % 26])
    return "".join(result)


def vig_encrypt(pt: str, key: str, alpha: str = AZ) -> str:
    """Vigenere encryption: ``CT[i] = (PT[i] + key[i]) mod 26``."""
    result = []
    for i, c in enumerate(pt):
        pi = alpha.index(c)
        ki = alpha.index(key[i % len(key)])
        result.append(alpha[(pi + ki) % 26])
    return "".join(result)


def beau_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    """Beaufort decryption: ``PT[i] = (key[i] - CT[i]) mod 26``."""
    result = []
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % len(key)])
        result.append(alpha[(ki - ci) % 26])
    return "".join(result)


# ── Permutation functions ────────────────────────────────────────────────────


def apply_permutation(text: str, perm: list[int] | tuple[int, ...]) -> str:
    """Gather convention: ``output[i] = text[perm[i]]``."""
    return "".join(text[p] for p in perm)


# ── Canonical test functions ─────────────────────────────────────────────────


def test_perm(sigma: list[int]) -> dict:
    """Test a permutation that maps real_CT positions to carved positions.

    ``real_CT[j] = K4_CARVED[sigma[j]]`` for ``j`` in ``0..96``.

    Tries all keywords x cipher types x alphabets.  Returns a dict with the
    best result, including any crib hits.  The ``"crib_hit"`` key is ``True``
    when EASTNORTHEAST or BERLINCLOCK is found anywhere in the plaintext.
    """
    real_ct = "".join(K4_CARVED[sigma[j]] for j in range(97))
    best: dict | None = None

    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [
                ("vig", vig_decrypt),
                ("beau", beau_decrypt),
            ]:
                try:
                    pt = cipher_fn(real_ct, kw, alpha)
                except (ValueError, IndexError):
                    continue

                # Check cribs at their expected plaintext positions
                ene_ok = pt[21:34] == "EASTNORTHEAST"
                bc_ok = pt[63:74] == "BERLINCLOCK"

                # Also search anywhere
                ene_any = pt.find("EASTNORTHEAST")
                bc_any = pt.find("BERLINCLOCK")

                sc = score_text(pt)

                if ene_ok or bc_ok or ene_any >= 0 or bc_any >= 0:
                    return {
                        "pt": pt,
                        "real_ct": real_ct,
                        "score": sc,
                        "score_per_char": sc / max(1, len(pt) - 3),
                        "key": kw,
                        "cipher": cipher_name,
                        "alpha": alpha_name,
                        "ene_at_21": ene_ok,
                        "bc_at_63": bc_ok,
                        "ene_anywhere": ene_any,
                        "bc_anywhere": bc_any,
                        "crib_hit": True,
                    }

                if best is None or sc > best["score"]:
                    best = {
                        "pt": pt,
                        "real_ct": real_ct,
                        "score": sc,
                        "score_per_char": sc / max(1, len(pt) - 3),
                        "key": kw,
                        "cipher": cipher_name,
                        "alpha": alpha_name,
                        "crib_hit": False,
                    }

    return best  # type: ignore[return-value]


def test_unscramble(candidate_ct: str) -> dict | None:
    """Try all keywords x ciphers x alphabets on a candidate real CT.

    Returns best result dict if score is interesting, else ``None``.
    """
    best_score = -999999.0
    best: dict | None = None

    for key in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [
                ("vig", vig_decrypt),
                ("beau", beau_decrypt),
            ]:
                try:
                    pt = cipher_fn(candidate_ct, key, alpha)
                except (ValueError, IndexError):
                    continue

                crib_hits = has_cribs(pt)
                sc = score_text(pt)

                if sc > best_score:
                    best_score = sc
                    best = {
                        "candidate_ct": candidate_ct,
                        "plaintext": pt,
                        "score": sc,
                        "keyword": key,
                        "cipher": cipher_name,
                        "alphabet": alpha_name,
                        "crib_hits": crib_hits,
                    }

                # Immediate return on crib hit
                if crib_hits:
                    return best

    # Only return if score is notably above random
    if best and best_score > -400:
        return best
    return None
