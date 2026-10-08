"""Public-reproduction shim for cryptolab.tools.transforms.

cribsolve.py imports the general transform engine at load time; the DOT-STANDING paths never
call it. This shim raises if one ever does.
"""


def apply_transform(*args, **kwargs):
    raise RuntimeError("the general transform engine is not part of the DOT-STANDING searches")
