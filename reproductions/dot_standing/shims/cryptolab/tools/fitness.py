"""Public-reproduction shim for cryptolab.tools.fitness.

The DOT-STANDING searches are exact crib-compatibility tests with no language gate. cribsolve.py
imports the language scorer at load time but these paths never call it; this shim raises if one
ever does, so a successful replay is evidence that no language scoring took part.
"""


def _not_part_of_these_searches(*args, **kwargs):
    raise RuntimeError("language scoring is not part of the DOT-STANDING searches")


quadgram_score = score = is_english = _not_part_of_these_searches
