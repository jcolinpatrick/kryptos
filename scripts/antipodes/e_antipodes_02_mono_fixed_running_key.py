#!/usr/bin/env python3
"""
Cipher: running key
Family: antipodes
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-ANTIPODES-02: Fixed Mono + Transposition + Running Key Detection

HYPOTHESIS: E-FRAC-54 proved Mono+Trans+Running_key is UNDERDETERMINED with
free mono. But if we FIX the mono layer to a publicly-derived alphabet (KA,
PALIMPSEST-keyed, ABSCISSA-keyed, etc.), underdetermination collapses and
running key detection becomes feasible.

WHY ANTIPODES: Sanborn says "kryptos is available to all" → the mono layer
isn't random; it comes from public information.

METHOD:
1. Define ~35 mono substitutions from publicly-known alphabets
2. For each: apply mono to CT → intermediate
3. For each transposition (columnar w6-13):
   - Apply inverse transposition
   - At crib positions, recover key values for Vig/Beau/VarBeau
   - Score key fragments using quadgram analysis
   - Compare vs E-FRAC-51 thresholds: random best = -4.151, English 5th = -3.551

COST: ~35 mono × 50K transpositions × 3 variants ≈ 5.25M configs. ~5 min.
"""

import json
import os
import sys
import time
import itertools
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_recover_key, beau_recover_key, varbeau_recover_key,
    vig_decrypt, beau_decrypt, varbeau_decrypt, decrypt_text,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.alphabet import keyword_mixed_alphabet, Alphabet

# ── Quadgram scorer ───────────────────────────────────────────────────────

QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')

def load_quadgrams() -> Optional[Dict[str, float]]:
    for path in [QUADGRAM_PATH,
                 os.path.join(os.path.dirname(__file__), '..', 'results',
                              'anneal_step7_start8', 'english_quadgrams.json')]:
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            if "logp" in data:
                data = data["logp"]
            return data
    return None

def score_quadgrams(text: str, qg: Dict[str, float], floor: float = -10.0) -> float:
    text = text.upper()
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        gram = text[i:i+4]
        total += qg.get(gram, floor)
        count += 1
    return total / count if count > 0 else floor

# ── Mono substitution definitions ─────────────────────────────────────────

def build_mono_alphabets() -> List[Tuple[str, str]]:
    """Build list of (name, alphabet_string) for mono substitution layer."""
    monos = []
    # Identity (no mono layer)
    monos.append(("identity", ALPH))

    # KA alphabet as substitution
    monos.append(("KA", KRYPTOS_ALPHABET))

    # Keyword-mixed alphabets
    keywords = [
        "PALIMPSEST", "ABSCISSA", "KRYPTOS", "BERLIN", "SANBORN",
        "SCHEIDT", "SHADOW", "ENIGMA", "QUARTZ", "CLOCK",
        "CARTER", "EGYPT", "HIEROGLYPH", "PHARAOH", "SPHINX",
        "TUTANKHAMUN", "URANIA", "COMPASS", "LODESTONE", "POINT",
        "ALEXANDERPLATZ", "WELTZEITUHR", "MENGENLEHREUHR",
    ]
    for kw in keywords:
        seq = keyword_mixed_alphabet(kw, ALPH)
        monos.append((f"{kw}(AZ)", seq))

    # Reversed alphabets
    monos.append(("AZ_rev", ALPH[::-1]))
    monos.append(("KA_rev", KRYPTOS_ALPHABET[::-1]))

    # Atbash (A↔Z, B↔Y, ...)
    monos.append(("Atbash", "".join(chr(155 - ord(c)) for c in ALPH)))  # 155 = 65+90

    # Caesar shifts (just a few key ones)
    for shift in [1, 3, 7, 13, 17, 25]:
        shifted = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in ALPH)
        monos.append((f"Caesar_{shift}", shifted))

    # Deduplicate
    seen = set()
    unique = []
    for name, seq in monos:
        if seq not in seen:
            seen.add(seq)
            unique.append((name, seq))

    return unique


def apply_mono_sub(text: str, alpha: str) -> str:
    """Apply mono substitution: letter at position i in ALPH maps to alpha[i].
    To reverse: text char c → find c in alpha → map to ALPH[pos].
    For decryption direction: CT was encrypted with alpha, so
    PT = ALPH[alpha.index(CT_char)].
    """
    idx = {c: i for i, c in enumerate(alpha)}
    return "".join(ALPH[idx[c]] for c in text)


KEY_RECOVER = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}

DECRYPT_FN = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}


def generate_column_orderings(width: int, max_orderings: int = 5040):
    """Generate column orderings. Full permutations for width <= 7, sampled for larger."""
    if width <= 7:
        yield from itertools.permutations(range(width))
    else:
        from kryptos.kernel.alphabet import THEMATIC_KEYWORDS
        seen = set()
        all_keywords = list(THEMATIC_KEYWORDS) + [
            "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "SANBORN",
            "SCHEIDT", "SHADOW", "ENIGMA", "HILL", "CIPHER",
            "EASTNORTHEAST", "BERLINCLOCK", "CARTER", "EGYPT",
        ]
        for kw in all_keywords:
            order = keyword_to_order(kw, width)
            if order is not None and order not in seen:
                seen.add(order)
                yield order
        import random
        rng = random.Random(42)
        attempts = 0
        while len(seen) < max_orderings and attempts < max_orderings * 5:
            perm_list = list(range(width))
            rng.shuffle(perm_list)
            t = tuple(perm_list)
            if t not in seen:
                seen.add(t)
                yield t
            attempts += 1


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-02: Fixed Mono + Transposition + Running Key")
    print("=" * 70)

    qg = load_quadgrams()
    if qg is None:
        print("WARNING: Quadgram file not found. Key quality scoring disabled.")
        qg_floor = -10.0
    else:
        qg_floor = min(qg.values())
        print(f"Loaded {len(qg)} quadgrams (floor={qg_floor:.3f})")

    monos = build_mono_alphabets()
    print(f"Testing {len(monos)} mono substitutions")

    # Thresholds from E-FRAC-51
    RANDOM_CEILING = -4.151  # Best quadgram score from random keys
    ENGLISH_FLOOR = -3.551   # 5th percentile of English text

    best_result = None
    best_key_score = -999.0
    best_crib_score = 0
    total_configs = 0
    above_threshold = []

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    for mono_name, mono_alpha in monos:
        # Apply mono decryption to CT
        mono_decoded = apply_mono_sub(CT, mono_alpha)

        for width in range(6, 14):
            for col_order in generate_column_orderings(width):
                perm = columnar_perm(width, col_order, CT_LEN)
                if not validate_perm(perm, CT_LEN):
                    continue
                inv_p = invert_perm(perm)
                intermediate = apply_perm(mono_decoded, inv_p)

                for variant in variants:
                    total_configs += 1
                    recover_fn = KEY_RECOVER[variant]

                    # Recover key at crib positions
                    key_vals = {}
                    for pos, pt_char in CRIB_DICT.items():
                        c = ord(intermediate[pos]) - 65
                        p = ord(pt_char) - 65
                        key_vals[pos] = recover_fn(c, p)

                    # Extract key as string for quadgram scoring
                    key_positions = sorted(key_vals.keys())
                    key_str = "".join(chr(key_vals[p] + 65) for p in key_positions)

                    # Score key fragment quality
                    if qg is not None and len(key_str) >= 4:
                        key_qg = score_quadgrams(key_str, qg, qg_floor)
                    else:
                        key_qg = qg_floor

                    # Quick filter: only pursue if key quality is promising
                    if key_qg > RANDOM_CEILING:
                        # Full decrypt with a running key derived from key_str pattern
                        # For now, record the finding
                        result = {
                            "mono": mono_name,
                            "width": width,
                            "col_order": list(col_order)[:8],  # truncate for readability
                            "variant": variant.value,
                            "key_fragment": key_str,
                            "key_quadgram": key_qg,
                            "key_positions": key_positions,
                        }
                        above_threshold.append(result)

                        if key_qg > best_key_score:
                            best_key_score = key_qg
                            best_result = result
                            print(f"NEW BEST key quality: {key_qg:.3f}/char, "
                                  f"mono={mono_name}, w={width}, {variant.value}")
                            print(f"  Key fragment: {key_str}")
                            if key_qg > ENGLISH_FLOOR:
                                print(f"  *** ABOVE ENGLISH FLOOR ({ENGLISH_FLOOR}) ***")

        if total_configs % 100000 == 0 and total_configs > 0:
            print(f"  Progress: {total_configs:,} configs, "
                  f"{len(above_threshold)} above threshold, "
                  f"best key qg={best_key_score:.3f}")

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Above random ceiling ({RANDOM_CEILING}): {len(above_threshold)}")
    print(f"Best key quadgram: {best_key_score:.3f}/char")
    if best_result:
        print(f"Best config: mono={best_result['mono']}, w={best_result['width']}, "
              f"{best_result['variant']}")
        print(f"Best key fragment: {best_result['key_fragment']}")
    if best_key_score > ENGLISH_FLOOR:
        print(f"\n*** SIGNAL: Key quality above English floor ({ENGLISH_FLOOR}) ***")
    elif best_key_score > RANDOM_CEILING:
        print(f"\nMarginal: Key quality between random ({RANDOM_CEILING}) and English ({ENGLISH_FLOOR})")
    else:
        print(f"\nNOISE: All key qualities below random ceiling ({RANDOM_CEILING})")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Write results ─────────────────────────────────────────────────────
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_02')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-02",
        "hypothesis": "Fixed mono substitution + transposition + running key",
        "total_configs": total_configs,
        "above_random_ceiling": len(above_threshold),
        "best_key_quadgram": best_key_score,
        "best_result": best_result,
        "random_ceiling": RANDOM_CEILING,
        "english_floor": ENGLISH_FLOOR,
        "mono_count": len(monos),
        "elapsed_seconds": elapsed,
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    if above_threshold:
        # Save top 100
        above_threshold.sort(key=lambda x: x["key_quadgram"], reverse=True)
        with open(os.path.join(outdir, 'above_threshold.json'), 'w') as f:
            json.dump(above_threshold[:100], f, indent=2)

    print(f"\nResults written to {outdir}/")


if __name__ == "__main__":
    main()
