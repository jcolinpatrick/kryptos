"""
Constants bridge — single import point for kryptosbot modules.

Imports from kryptos.kernel.constants (the single source of truth).
Includes sys.path fallback for multiprocessing workers that may not
inherit PYTHONPATH=src.

Usage:
    from kryptosbot.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ
"""
from __future__ import annotations

import os
import sys

try:
    from kryptos.kernel.constants import (  # noqa: F401
        CT, CT_LEN,
        ALPH, ALPH_IDX, MOD,
        KRYPTOS_ALPHABET,
        CRIB_WORDS, CRIB_ENTRIES, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
        BEAN_EQ, BEAN_INEQ,
        NULL_PALETTE, CONSENSUS_NULL_POSITIONS,
        BEAUFORT_KEYSTREAM_AT_CRIBS,
        BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
        VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
        NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
    )
except ImportError:
    # Multiprocessing worker fallback: PYTHONPATH may not be set
    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(_ROOT, "src"))
    from kryptos.kernel.constants import (  # noqa: F401
        CT, CT_LEN,
        ALPH, ALPH_IDX, MOD,
        KRYPTOS_ALPHABET,
        CRIB_WORDS, CRIB_ENTRIES, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
        BEAN_EQ, BEAN_INEQ,
        NULL_PALETTE, CONSENSUS_NULL_POSITIONS,
        BEAUFORT_KEYSTREAM_AT_CRIBS,
        BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
        VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
        NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
    )

# Convenience aliases matching names used across kryptosbot modules
K4 = CT
K4_LEN = CT_LEN
AZ = ALPH
KA = KRYPTOS_ALPHABET
CRIBS = list(CRIB_WORDS)  # [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
