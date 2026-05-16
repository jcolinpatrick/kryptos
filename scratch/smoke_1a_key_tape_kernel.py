"""Smoke test 1a: apply_key_tape against real K4 CT with a fixed random tape.

Goal: confirm the new kernel transform runs end-to-end on the 97-char target
without crashing. All 6 (variant x alphabet) combinations should print a
97-char string. Output is almost certainly noise — that's expected.

Run: PYTHONPATH=src python3 scratch/smoke_1a_key_tape_kernel.py
"""
import random

from kryptos.kernel.constants import CT
from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.transforms.key_tape import apply_key_tape
from kryptos.kernel.transforms.vigenere import CipherVariant

random.seed(42)
tape = tuple(random.randint(0, 25) for _ in range(97))

print(f"K4 CT (97 chars): {CT}")
print(f"Random tape (seed=42, len=97): first 20 = {tape[:20]}")
print()

for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
    for alphabet in [AZ, KA]:
        pt = apply_key_tape(
            CT,
            tape=tape,
            variant=variant,
            direction="decrypt",
            alphabet=alphabet,
        )
        print(f"{variant.value:14s} {alphabet.label}: {pt}")
        print(f"{' ' * 18}cribs 21-33: {pt[21:34]}  cribs 63-73: {pt[63:74]}")
        print()

print("All 6 variant x alphabet combinations executed cleanly.")
