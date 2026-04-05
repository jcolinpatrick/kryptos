#!/usr/bin/env python3
"""
Cipher: Key unmasking — systematic transforms on derived keystream
Family: novel
Status: active
Keyspace: ~28K compositions × 3 variants × ~48 output alphabets
Last run: 2026-04-05
Best score: 0.0 (key_word_coverage)
Credit: Kimmo (community) — idea that the key itself may be encrypted
"""
import sys
import os
import itertools

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAUFORT_KEYSTREAM_AT_CRIBS, CT, CRIB_DICT,
)
from kryptos.kernel.alphabet import (
    keyword_mixed_alphabet, Alphabet, AZ, KA, THEMATIC_KEYWORDS,
)
from kryptos.kernel.scoring.words import WordScorer

# ── Derive Variant Beaufort keystream ──────────────────────────────────────

VARBEAU_KEY_ENE = tuple(
    (ALPH_IDX[CRIB_DICT[p]] - ALPH_IDX[CT[p]]) % MOD for p in range(21, 34)
)
VARBEAU_KEY_BC = tuple(
    (ALPH_IDX[CRIB_DICT[p]] - ALPH_IDX[CT[p]]) % MOD for p in range(63, 74)
)

VARIANT_KEYS = {
    "vigenere":     (VIGENERE_KEY_ENE, VIGENERE_KEY_BC),
    "beaufort":     (BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC),
    "var_beaufort": (VARBEAU_KEY_ENE, VARBEAU_KEY_BC),
}

# ── Self-test ──────────────────────────────────────────────────────────────

_beau_check = "".join(ALPH[v] for v in BEAUFORT_KEY_ENE + BEAUFORT_KEY_BC)
assert _beau_check == BEAUFORT_KEYSTREAM_AT_CRIBS, "Beaufort keystream mismatch"

# ── Build transform catalog ───────────────────────────────────────────────

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}


def _rot(n):
    """ROT-N: shift all values by n mod 26."""
    def fn(vals):
        return tuple((v + n) % MOD for v in vals)
    fn.__name__ = f"ROT({n})"
    return fn


def _atbash_az(vals):
    """ATBASH in AZ space: v -> 25-v."""
    return tuple((25 - v) % MOD for v in vals)
_atbash_az.__name__ = "ATBASH_AZ"


def _atbash_ka(vals):
    """ATBASH in KA space: map through KA, reverse, map back."""
    return tuple(
        ALPH_IDX[KRYPTOS_ALPHABET[25 - KA_IDX[ALPH[v]]]]
        for v in vals
    )
_atbash_ka.__name__ = "ATBASH_KA"


def _subst_az_to_ka(vals):
    """SUBST AZ->KA: treat value as AZ index, return KA index of same letter."""
    return tuple(KA_IDX[ALPH[v]] for v in vals)
_subst_az_to_ka.__name__ = "SUBST_AZ→KA"


def _subst_ka_to_az(vals):
    """SUBST KA->AZ: treat value as KA index, return AZ index of same letter."""
    return tuple(ALPH_IDX[KRYPTOS_ALPHABET[v]] for v in vals)
_subst_ka_to_az.__name__ = "SUBST_KA→AZ"


def _reverse(vals):
    """Reverse the fragment order."""
    return vals[::-1]
_reverse.__name__ = "REVERSE"


def build_transform_catalog():
    """Build the catalog of ~30 single transforms."""
    transforms = []
    for n in range(1, 26):
        transforms.append((_rot(n).__name__, _rot(n)))
    transforms.append((_atbash_az.__name__, _atbash_az))
    transforms.append((_atbash_ka.__name__, _atbash_ka))
    transforms.append((_subst_az_to_ka.__name__, _subst_az_to_ka))
    transforms.append((_subst_ka_to_az.__name__, _subst_ka_to_az))
    transforms.append((_reverse.__name__, _reverse))
    return transforms


def build_output_alphabets():
    """Build alphabets through which to convert key values to letters."""
    alphs = [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]
    seen = {ALPH, KRYPTOS_ALPHABET}
    for kw in THEMATIC_KEYWORDS:
        for base in [ALPH, KRYPTOS_ALPHABET]:
            seq = keyword_mixed_alphabet(kw, base)
            if seq not in seen:
                seen.add(seq)
                label = f"{kw}({'KA' if base == KRYPTOS_ALPHABET else 'AZ'})"
                alphs.append((label, seq))
    return alphs


def vals_to_text(vals, alphabet_str):
    """Convert numeric key values to text through an alphabet."""
    return "".join(alphabet_str[v] for v in vals)


def attack(ciphertext: str = CT, **params):
    """Key unmasking attack: apply systematic transforms to known keystream."""
    max_depth = params.get("max_depth", 3)
    min_coverage = params.get("min_coverage", 0.30)
    min_word_len = params.get("min_word_len", 4)

    ws = WordScorer.from_file(os.path.join(_ROOT, "wordlists", "english.txt"),
                              min_word_len=min_word_len)
    catalog = build_transform_catalog()
    output_alphs = build_output_alphabets()

    results = []
    tested = 0

    for variant, (ene_key, bc_key) in VARIANT_KEYS.items():
        combined_key = ene_key + bc_key  # 24 values

        # Enumerate compositions up to max_depth
        for depth in range(1, max_depth + 1):
            for combo in itertools.product(catalog, repeat=depth):
                names = [c[0] for c in combo]
                fns = [c[1] for c in combo]

                # Apply transforms sequentially
                transformed = combined_key
                for fn in fns:
                    transformed = fn(transformed)

                # Also apply to ENE and BC fragments separately
                t_ene = transformed[:13]
                t_bc = transformed[13:]

                # Convert through each output alphabet
                for alph_label, alph_str in output_alphs:
                    tested += 1
                    text_24 = vals_to_text(transformed, alph_str)
                    text_ene = vals_to_text(t_ene, alph_str)
                    text_bc = vals_to_text(t_bc, alph_str)

                    # Score the 13-char ENE fragment (most promising for word detection)
                    cov_ene = ws.score_coverage(text_ene)
                    cov_bc = ws.score_coverage(text_bc)
                    cov_24 = ws.score_coverage(text_24)

                    best_cov = max(cov_ene, cov_bc, cov_24)
                    if best_cov >= min_coverage:
                        # Full word analysis
                        wr = ws.score(text_24)
                        chain = " → ".join(names)
                        desc = (f"{variant}/{chain}/out={alph_label} "
                                f"key_24={text_24} "
                                f"ene={text_ene}({cov_ene:.2f}) "
                                f"bc={text_bc}({cov_bc:.2f}) "
                                f"words={wr.words}")
                        results.append((best_cov, text_24, desc))

    results.sort(reverse=True)
    return results, tested


def main():
    print("=" * 70)
    print("KEY UNMASKING — Systematic transforms on known keystream")
    print("Credit: Kimmo (community idea)")
    print("=" * 70)

    # Show baseline keystream (no transform)
    ws = WordScorer.from_file(os.path.join(_ROOT, "wordlists", "english.txt"),
                              min_word_len=4)
    for variant, (ene_key, bc_key) in VARIANT_KEYS.items():
        combined = ene_key + bc_key
        text = vals_to_text(combined, ALPH)
        wr = ws.score(text)
        print(f"\n  {variant:15s} raw key (AZ): {text}  "
              f"coverage={wr.coverage:.2f} words={wr.words}")

    print("\n" + "-" * 70)
    print("Searching depth 1-3 compositions × 3 variants × all output alphabets...")
    results, tested = attack()

    print(f"\nTested {tested:,} configurations")
    print(f"Found {len(results)} results above threshold\n")

    if results:
        print("Top 30 results:")
        print("-" * 70)
        for i, (score, key_text, desc) in enumerate(results[:30]):
            print(f"  [{i+1:2d}] coverage={score:.2f}  {desc}")
    else:
        print("No results above threshold.")

    print("\n" + "=" * 70)
    print(f"VERDICT: {'SIGNAL — investigate top results' if any(s >= 0.50 for s, _, _ in results) else 'No signal found'}")
    print("=" * 70)


if __name__ == "__main__":
    main()
