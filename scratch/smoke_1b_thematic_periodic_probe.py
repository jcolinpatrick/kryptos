"""Smoke test 1b: short thematic words tiled across 97 chars, count crib hits.

NOTE: this is a periodic-Vigenere probe (the same word repeated), not a true
key_tape non-repeating-tape attack. But it's the cheapest way to confirm any
hits at known crib positions. Stage A was a clean negative for periodic-style
hypotheses, so we expect random-noise levels here too (mean ~0.92/24 hits).

Anything >5/24 is suspicious. >10 is a flag worth red-teaming.

Run: PYTHONPATH=src python3 scratch/smoke_1b_thematic_periodic_probe.py
"""
from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.transforms.key_tape import apply_key_tape
from kryptos.kernel.transforms.vigenere import CipherVariant

WORDS = [
    "BERLIN", "LANGLEY", "WALLACE", "LATITUDE", "LONGITUDE",
    "SHADOWS", "PALIMPSEST", "ABSCISSA", "KRYPTOS",
    "EASTNORTHEAST", "BERLINCLOCK", "VIRGINIA",
]

print(f"Crib positions ({len(CRIB_DICT)}): {sorted(CRIB_DICT.keys())}")
print(f"Crib values: {sorted(CRIB_DICT.items())}")
print()

best_hits = 0
best_config = None

for word in WORDS:
    word = word.upper()
    # Tile the word across 97 chars
    tiled = (word * ((97 // len(word)) + 1))[:97]
    tape = tuple(ord(c) - ord("A") for c in tiled)

    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        for alphabet in [AZ, KA]:
            pt = apply_key_tape(
                CT,
                tape=tape,
                variant=variant,
                direction="decrypt",
                alphabet=alphabet,
            )
            hits = sum(1 for p, c in CRIB_DICT.items() if pt[p] == c)
            if hits > best_hits:
                best_hits = hits
                best_config = (word, variant.value, alphabet.label, pt)
            tag = "  <-- !!" if hits >= 5 else ""
            print(f"{word:14s} {variant.value:14s} {alphabet.label}: {hits:2d}/24 hits  pt[21:34]={pt[21:34]}{tag}")

print()
if best_config:
    word, variant, alphabet, pt = best_config
    print(f"Best: {word} / {variant} / {alphabet} → {best_hits}/24 hits")
    print(f"  Full PT: {pt}")
print(f"\n(Random expectation under uniform alphabet ≈ 0.92/24. >5 is worth a second look.)")
