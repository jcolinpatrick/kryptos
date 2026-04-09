"""Atbash substitution: fixed involution over the alphabet.

Atbash is a monoalphabetic substitution defined by the fixed involution
A <-> Z, B <-> Y, ..., M <-> N. It has no key parameter; it is its own
inverse. The cipher equation is:

    C[i] = (MOD - 1 - P[i]) mod MOD      (encryption)
    P[i] = (MOD - 1 - C[i]) mod MOD      (decryption, same as encryption)

This module exists because `kryptos.admissibility.procedure_policy` pins
the `atbash_substitution_layer` license to this parametric spec. Any
script claiming that license MUST operate through this module rather
than re-implementing Atbash inline, so that all "ATBASH" claims in the
project operationalize the exact same definition.

Design notes:
  - Atbash is a special case of affine `(a, b) = (25, 25)` and also a
    special case of Vigenere with key `[25] * n` under the C = P + K
    convention. We prefer the explicit direct form here for clarity
    and because Sanborn's archive names "Atbash" as the construction,
    not "affine with those parameters".
  - Like other kernel transforms, this module operates on plain ASCII
    uppercase strings. Non-alphabetic input is not tolerated; callers
    must sanitise via `kryptos.kernel.text.sanitize` first.
  - Atbash is self-reciprocal: encrypt and decrypt are the same
    function. Both names are provided to make callers' intent explicit.
"""
from __future__ import annotations

from kryptos.kernel.constants import ALPH, ALPH_IDX, MOD


def _atbash_one(ch: str) -> str:
    """Apply the Atbash involution to a single uppercase letter."""
    return ALPH[(MOD - 1 - ALPH_IDX[ch]) % MOD]


def encrypt_atbash(plaintext: str) -> str:
    """Return the Atbash encryption of `plaintext`.

    Atbash is self-reciprocal, so `decrypt_atbash` is an alias for
    this function.
    """
    return "".join(_atbash_one(ch) for ch in plaintext)


def decrypt_atbash(ciphertext: str) -> str:
    """Return the Atbash decryption of `ciphertext`.

    Atbash is self-reciprocal, so this is equivalent to
    `encrypt_atbash(ciphertext)`.
    """
    return "".join(_atbash_one(ch) for ch in ciphertext)
