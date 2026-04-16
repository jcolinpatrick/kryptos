"""
Constants bridge — single import point for kryptosbot modules.

Imports from kryptos.kernel.constants (the single source of truth).
Includes sys.path fallback for multiprocessing workers that may not
inherit PYTHONPATH=src.

Usage:
    from kryptosbot.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ

QUARANTINE 2026-04-14: NULL_PALETTE and CONSENSUS_NULL_POSITIONS are no
longer eagerly re-exported by this shim. They remain accessible via
module-level __getattr__ (below) but any access emits a
DeprecationWarning. This prevents a worker writing
`from kryptosbot.constants import NULL_PALETTE` from silently
bypassing the canonical_facts quarantine. See:
memory/project_consensus_nulls_epistemic_status_2026_04_14.md.
"""
from __future__ import annotations

import os
import sys
import warnings

try:
    from kryptos.kernel.constants import (  # noqa: F401
        CT, CT_LEN,
        ALPH, ALPH_IDX, MOD,
        KRYPTOS_ALPHABET,
        CRIB_WORDS, CRIB_ENTRIES, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
        BEAN_EQ, BEAN_INEQ,
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
        BEAUFORT_KEYSTREAM_AT_CRIBS,
        BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
        VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
        NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
    )


# Quarantine hook: intercept access to retired palette symbols via the
# shim. The kernel still exports them (for historical reproducibility
# under Commit 6's relaxed _verify), but any path that reaches them
# through `kryptosbot.constants.NULL_PALETTE` or
# `from kryptosbot.constants import NULL_PALETTE` will now trigger a
# DeprecationWarning and be flagged in the logs.
_RETIRED_PALETTE_SYMBOLS = frozenset({"NULL_PALETTE", "CONSENSUS_NULL_POSITIONS"})


def __getattr__(name: str):
    if name in _RETIRED_PALETTE_SYMBOLS:
        warnings.warn(
            f"kryptosbot.constants.{name} is a retired symbol "
            f"(claim_id: null_palette_retired, retired 2026-04-14). "
            f"The shim access is intercepted to prevent silent bypass "
            f"of the canonical_facts quarantine. If you genuinely need "
            f"the historical value for reproducibility or a regression "
            f"fixture, import it directly from kryptos.kernel.constants "
            f"and document the use. See "
            f"memory/project_consensus_nulls_epistemic_status_2026_04_14.md.",
            DeprecationWarning,
            stacklevel=2,
        )
        from kryptos.kernel import constants as _kc
        return getattr(_kc, name)
    raise AttributeError(f"module 'kryptosbot.constants' has no attribute {name!r}")

# Convenience aliases matching names used across kryptosbot modules
K4 = CT
K4_LEN = CT_LEN
AZ = ALPH
KA = KRYPTOS_ALPHABET
CRIBS = list(CRIB_WORDS)  # [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
