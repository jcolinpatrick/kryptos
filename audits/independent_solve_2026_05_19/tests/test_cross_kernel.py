"""Cross-verify the reference impl agrees with the kernel on representative
classical-cipher operations applied to the K4 ciphertext. Any disagreement
is a hard halt — at least one of the two implementations has a bug, and a
Tier 1 elimination citing the buggy one cannot be trusted.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(ROOT))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(ROOT)), "src"))

from independent_solve_2026_05_19.src.alphabets import AZ, KA
from independent_solve_2026_05_19.src.ciphers.vigenere import decrypt as ref_vig_decrypt
from independent_solve_2026_05_19.src.ciphers.beaufort import (
    beaufort_decrypt as ref_beau_decrypt,
    variant_beaufort_decrypt as ref_vbeau_decrypt,
)

from kryptos.kernel.constants import CT
from kryptos.kernel.alphabet import AZ as KERNEL_AZ, KA as KERNEL_KA
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant


def kernel_decrypt(variant_name, key_str, kernel_alpha, ref_alpha):
    """Call kernel decrypt with a key converted to per-position ints in
    the *kernel* alphabet, repeated to CT length."""
    cv = {"vig": CipherVariant.VIGENERE,
          "beau": CipherVariant.BEAUFORT,
          "vbeau": CipherVariant.VAR_BEAUFORT}[variant_name]
    n = len(CT)
    key_letters = (key_str * ((n // len(key_str)) + 1))[:n]
    key_ints = [kernel_alpha.char_to_idx(c) for c in key_letters]
    return decrypt_text(CT, key_ints, variant=cv, alphabet=kernel_alpha)


CASES = [
    ("Vigenere KRYPTOS AZ",          "vig",   "KRYPTOS",       AZ,  KERNEL_AZ),
    ("Vigenere KRYPTOS KA",          "vig",   "KRYPTOS",       KA,  KERNEL_KA),
    ("Vigenere PALIMPSEST AZ",       "vig",   "PALIMPSEST",    AZ,  KERNEL_AZ),
    ("Vigenere ABSCISSA KA",         "vig",   "ABSCISSA",      KA,  KERNEL_KA),
    ("Vigenere BERLINCLOCK AZ",      "vig",   "BERLINCLOCK",   AZ,  KERNEL_AZ),
    ("Vigenere EASTNORTHEAST KA",    "vig",   "EASTNORTHEAST", KA,  KERNEL_KA),
    ("Beaufort KRYPTOS AZ",          "beau",  "KRYPTOS",       AZ,  KERNEL_AZ),
    ("Beaufort BERLINCLOCK KA",      "beau",  "BERLINCLOCK",   KA,  KERNEL_KA),
    ("VarBeaufort PALIMPSEST AZ",    "vbeau", "PALIMPSEST",    AZ,  KERNEL_AZ),
    ("VarBeaufort EASTNORTHEAST KA", "vbeau", "EASTNORTHEAST", KA,  KERNEL_KA),
]


def main():
    failures = []
    for name, op, key, ref_alpha, ker_alpha in CASES:
        if op == "vig":
            ref_out = ref_vig_decrypt(CT, key, ref_alpha)
        elif op == "beau":
            ref_out = ref_beau_decrypt(CT, key, ref_alpha)
        else:
            ref_out = ref_vbeau_decrypt(CT, key, ref_alpha)
        ker_out = kernel_decrypt(op, key, ker_alpha, ref_alpha)

        if ref_out != ker_out:
            n_match = sum(1 for a, b in zip(ref_out, ker_out) if a == b)
            failures.append(
                f"{name}: REF != KERNEL ({n_match}/{len(CT)} chars match)\n"
                f"    ref:    {ref_out}\n"
                f"    kernel: {ker_out}"
            )
            continue
        print(f"  OK  {name}  ->  {ref_out[:30]}...")

    if failures:
        print("\nCROSS-KERNEL VERIFICATION: FAIL")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print(f"\nCROSS-KERNEL VERIFICATION: PASS ({len(CASES)} cases)")


if __name__ == "__main__":
    main()
