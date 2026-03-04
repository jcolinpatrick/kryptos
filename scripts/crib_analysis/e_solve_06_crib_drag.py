#!/usr/bin/env python3
"""
Cipher: crib-based constraint
Family: crib_analysis
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-SOLVE-06: Crib Dragging and Plaintext Hypothesis Testing.

Instead of guessing the cipher, guess the PLAINTEXT.
If we extend the known cribs with plausible words, the resulting
keystream may reveal structure (periodicity, English text, etc.).

K4 structure:
  [0-20]  UNKNOWN (21 chars)
  [21-33] EASTNORTHEAST (known)
  [34-62] UNKNOWN (29 chars)
  [63-73] BERLINCLOCK (known)
  [74-96] UNKNOWN (23 chars)

Approach:
  1. Guess words adjacent to the known cribs
  2. Compute the implied keystream at those positions
  3. Check if the extended keystream shows periodicity or readability
  4. Try common K4-themed words at various positions via crib drag
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR,
)

CT_VALS = [ALPH_IDX[c] for c in CT]
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def compute_key(pt_text, start_pos, variant="vig"):
    """Compute keystream values for a plaintext guess at given position."""
    keys = {}
    for i, ch in enumerate(pt_text):
        pos = start_pos + i
        if pos >= CT_LEN:
            break
        pt_val = ALPH_IDX.get(ch.upper(), -1)
        if pt_val < 0:
            continue
        if variant == "vig":
            keys[pos] = (CT_VALS[pos] - pt_val) % 26
        elif variant == "beau":
            keys[pos] = (CT_VALS[pos] + pt_val) % 26
        else:  # varbeau
            keys[pos] = (pt_val - CT_VALS[pos]) % 26
    return keys


def check_periodicity(keys_dict, period):
    """Check if key values are consistent with a given period."""
    by_residue = {}
    for pos, kval in keys_dict.items():
        res = pos % period
        if res in by_residue:
            if by_residue[res] != kval:
                return False
        else:
            by_residue[res] = kval
    return True


def check_bean(keys_dict):
    """Check Bean constraints on extended keystream."""
    for a, b in BEAN_EQ:
        if a in keys_dict and b in keys_dict:
            if keys_dict[a] != keys_dict[b]:
                return False
    for a, b in BEAN_INEQ:
        if a in keys_dict and b in keys_dict:
            if keys_dict[a] == keys_dict[b]:
                return False
    return True


def key_is_readable(keys_dict):
    """Check if the keystream values spell something readable (running key)."""
    positions = sorted(keys_dict.keys())
    if len(positions) < 8:
        return False, ""

    text = ''.join(ALPH[keys_dict[p]] for p in positions)
    # Check vowel ratio
    vowels = sum(1 for c in text if c in 'AEIOU')
    ratio = vowels / len(text)
    return 0.25 <= ratio <= 0.55, text


# Build the base keystream from known cribs
BASE_KEYS = {}
for pos, ch in CRIB_DICT.items():
    BASE_KEYS[pos] = (CT_VALS[pos] - ALPH_IDX[ch]) % 26


def test_crib_extensions():
    """Test plaintext guesses adjacent to known cribs."""
    print("\n" + "=" * 70)
    print("TEST 1: Crib Extension — Words Before/After Known Cribs")
    print("=" * 70)

    # Words that might appear before EASTNORTHEAST (ending at position 20)
    before_ene = [
        # Directional/navigational
        ("BEARING", 14), ("HEADING", 14), ("COMPASS", 14),
        ("DIRECTION", 12), ("THEYWENT", 13),
        # Coordinate-related
        ("DEGREES", 14), ("LATITUDE", 13), ("LOCATION", 13),
        # Espionage
        ("PROCEED", 14), ("SIGNAL", 15), ("POSITION", 13),
        ("ITWAS", 16), ("SLOWLY", 15),
        # Carter/archaeology
        ("THEENTRY", 13), ("ENTRANCE", 13),
        # Generic connectors
        ("TOTHE", 16), ("FROMTHE", 14), ("OFTHE", 16),
        ("WASTHE", 15), ("ANDTHE", 15),
        # Full position-0 starts
        ("ITWASLIGHTLYTOTH", 0), ("THEYWENTSLOWLYTO", 0),
        ("SLOWLYTHEYMOVEDTO", 0),
        ("THEREWASNOTHINGTO", 0),
        ("HECOULDSEEFROMHIS", 0),
        ("ITWASSOMEWHERETO", 0),
    ]

    # Words that might appear after EASTNORTHEAST (starting at position 34)
    after_ene = [
        ("OFTHEBUILDING", 34), ("WASTHEPOINT", 34),
        ("ATTHECORNER", 34), ("NEARTHECORNER", 34),
        ("OFTHEMONUMENT", 34), ("ONTHEGROUND", 34),
        ("INTHESHADOW", 34), ("UNDERALIGHT", 34),
        ("ANDSLIGHTLY", 34), ("APPROXIMATELY", 34),
        ("ITWASTHERE", 34), ("THEYCOULDSE", 34),
        ("FROMTHERE", 34), ("HEWALKED", 34),
        ("THELOCATION", 34), ("THEPOINT", 34),
        ("WHATWASTHE", 34), ("COORDINATES", 34),
        ("FIFTYDEGREES", 34),
        # K2 reference: "THEY COULD SEE FROM THEIR POSITION SLIGHTLY TO THE EAST"
        ("THEYCOULDSEE", 34),
        ("FROMTHEIRPOSITION", 34),
    ]

    # Words between the cribs (positions 34-62, 29 chars)
    between = [
        ("ANDTHECOORDINATESWERE", 34),
        ("THELOCATIONWASMARKED", 34),
        ("HEWENTTOWARDTHEOLDWALL", 34),
        ("THEYWERELOCATEDATTHE", 34),
        ("ITREADTHEFOLLOWING", 34),
        ("NOTHINGWASLEFTEXCEPT", 34),
        ("BUTTHEREWASNOTHINGNO", 34),
    ]

    # Words before BERLINCLOCK (ending at position 62)
    before_bc = [
        ("ANDTHEOLD", 54), ("WASTHEOLD", 54),
        ("NEARTHEOLD", 53), ("ITWASTHE", 55),
        ("CALLEDTHE", 54), ("NAMEDTHE", 55),
        ("OFTHE", 58), ("ATTHE", 58),
        ("ISTHE", 58), ("TOTHE", 58),
        ("ANDTHE", 57), ("WASTHE", 57),
        ("NEARTHEWELTZEITUHR", 45),
    ]

    # Words after BERLINCLOCK (starting at position 74)
    after_bc = [
        # The last 23 characters
        ("WASTHEONLYCLUEREMAINING", 74),
        ("REMAINEDTHEONLYEVIDENCE", 74),
        ("ISNOLONGERSTANDINGTHERE", 74),
        ("WASDESTROYDBUTHEKNEWIT", 74),
        ("HADBEENREMOVEDLONGAGO", 74),
        ("SHOWEDTHEEXACTLOCATION", 74),
        ("REVEALDTHETRUTHABOUTIT", 74),
        ("WASALLTHATHEMEMBEREDX", 74),
        ("ITWASLIGHTLYPASTMIDNIG", 74),
        ("THEREWASNOONETHERENOW", 74),
        ("HECOULDNOTSEEANYTHING", 74),
        ("WASTHEKEYTOTHEPUZZLE", 74),
        ("MARKEDTHEEXACTLOCATION", 74),
        ("WHOWASRESPONSIBLEFORIT", 74),
        ("WASTHEANSWERTOTHECODED", 74),
        ("TOLDTHEMNOTHINGATALLX", 74),
        # Shorter guesses
        ("WASTHEANSWER", 74),
        ("ISTHEANSWERX", 74),
        ("NOTHINGREMAINS", 74),
        ("HERELIESTHETRUTH", 74),
        ("HASBEENDESTROYED", 74),
        ("THATISALLWEHAVEX", 74),
        ("WHOBUILTTHISKNEW", 74),
        ("BUTNOONECAMEBACK", 74),
        ("ANDHEWALKEDAWAY", 74),
    ]

    all_guesses = before_ene + after_ene + between + before_bc + after_bc
    results = []

    for guess_text, start_pos in all_guesses:
        guess_text = guess_text.upper()

        for variant in ["vig", "beau"]:
            # Compute extended keystream
            ext_keys = dict(BASE_KEYS)
            new_keys = compute_key(guess_text, start_pos, variant)
            ext_keys.update(new_keys)

            # Check Bean
            bean = check_bean(ext_keys)
            if not bean:
                continue  # Skip Bean-violating guesses

            # Check periodicity at discriminating periods
            for period in range(2, 8):
                if check_periodicity(ext_keys, period):
                    # Interesting! Record it
                    key_text = ''.join(ALPH[ext_keys.get(p, 0)]
                                       for p in sorted(ext_keys.keys()))
                    readable, key_str = key_is_readable(ext_keys)
                    results.append({
                        "guess": guess_text,
                        "start": start_pos,
                        "variant": variant,
                        "period": period,
                        "bean": True,
                        "readable": readable,
                        "n_known": len(ext_keys),
                    })
                    print(f"  PERIODIC! '{guess_text}'@{start_pos} ({variant}), "
                          f"period={period}, n_keys={len(ext_keys)}, "
                          f"readable={readable}")

            # Also check if extended key looks like English (running key hypothesis)
            readable, key_str = key_is_readable(ext_keys)
            if readable and len(ext_keys) >= 30:
                results.append({
                    "guess": guess_text,
                    "start": start_pos,
                    "variant": variant,
                    "readable": True,
                    "key_str": key_str[:50],
                    "n_known": len(ext_keys),
                })
                print(f"  READABLE KEY! '{guess_text}'@{start_pos} ({variant}), "
                      f"key={key_str[:30]}...")

    print(f"\n  Total guesses tested: {len(all_guesses) * 2}")
    print(f"  Results found: {len(results)}")
    return results


def test_word_crib_drag():
    """
    Drag common words through ALL positions and check if the resulting
    keystream becomes periodic or readable when combined with known cribs.
    """
    print("\n" + "=" * 70)
    print("TEST 2: Word Crib Drag — Systematic Position Scanning")
    print("=" * 70)

    words = [
        "SLOWLY", "DESPERATELY", "NOTHING", "EVERYTHING",
        "REMAINS", "INVISIBLE", "SHADOW", "DARKNESS", "LIGHT",
        "BURIED", "HIDDEN", "SECRET", "ANSWER", "CLUE",
        "POSITION", "LOCATION", "COMPASS", "DIRECTION",
        "ENTRANCE", "PASSAGE", "DOORWAY", "OPENING",
        "PHARAOH", "CARTER", "HOWARD", "EGYPT",
        "LANGLEY", "VIRGINIA", "AGENCY", "INTELLIGENCE",
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DIGETAL",
        "POINT", "WHATISTHEPOINT", "ONLYWWCANKNOWTHIS",
        "IQLUSION", "SUBTLESHADING",
        "THETRUTHIS", "THEREISNOANSWER",
        "COORDINATES", "LATITUDE", "LONGITUDE",
    ]

    best_periodic = None
    results = []

    for word in words:
        word = word.upper()
        wlen = len(word)

        for start in range(0, CT_LEN - wlen + 1):
            # Skip if overlaps with known cribs in a conflicting way
            conflict = False
            for i, ch in enumerate(word):
                pos = start + i
                if pos in CRIB_DICT and CRIB_DICT[pos] != ch:
                    conflict = True
                    break
            if conflict:
                continue

            for variant in ["vig", "beau"]:
                ext_keys = dict(BASE_KEYS)
                new_keys = compute_key(word, start, variant)
                ext_keys.update(new_keys)

                bean = check_bean(ext_keys)
                if not bean:
                    continue

                for period in range(2, 8):
                    if check_periodicity(ext_keys, period):
                        n_constraints = len(ext_keys)
                        redundancy = n_constraints - period
                        if redundancy >= period:
                            # Highly overconstrained and still periodic!
                            results.append({
                                "word": word,
                                "start": start,
                                "variant": variant,
                                "period": period,
                                "n_keys": n_constraints,
                                "redundancy": redundancy,
                            })
                            if best_periodic is None or redundancy > best_periodic["redundancy"]:
                                best_periodic = results[-1]

    if results:
        print(f"  Found {len(results)} periodic configs:")
        # Sort by redundancy
        results.sort(key=lambda r: -r["redundancy"])
        for r in results[:20]:
            print(f"    '{r['word']}'@{r['start']} ({r['variant']}): "
                  f"period={r['period']}, keys={r['n_keys']}, redundancy={r['redundancy']}")
    else:
        print("  No periodic configs found.")

    print(f"  Total word placements tested: ~{sum(CT_LEN - len(w) for w in words) * 2}")
    return results


def test_full_pt_hypotheses():
    """
    Test complete 97-character plaintext hypotheses.
    If a hypothesis produces a key with structure, it may be the solution.
    """
    print("\n" + "=" * 70)
    print("TEST 3: Full Plaintext Hypotheses")
    print("=" * 70)

    # Generate full PT candidates by filling in blanks with plausible text
    templates = [
        # Template 1: Carter's tomb narrative continuing
        "SLOWLYTHEYMOVEDTOTHE" + "EASTNORTHEAST" +
        "OFTHEENTRANCEUNTILTHEY" + "FOUND" +
        "BERLINCLOCK" + "WASTHEKEYTOTHEPUZZLEX",

        # Template 2: Espionage / dead drop
        "HECOULDSEEFROMHISPOS" + "EASTNORTHEAST" +
        "NEARTHECORNEROFTHESTO" + "NE" +
        "BERLINCLOCK" + "WASTHEONLYCLUEREMAINI",

        # Template 3: Self-referential loop
        "WHATISTHEPOINTOFALLA" + "EASTNORTHEAST" +
        "ISTHEDIRECTIONONLYTHE" + "OLD" +
        "BERLINCLOCK" + "CANREVEALWHATLIESHERE",

        # Template 4: K2-style continuation
        "THEYCOULDSEETHELIGHT" + "EASTNORTHEAST" +
        "WASVISIBLEFROMTHEPOSI" + "TION" +
        "BERLINCLOCK" + "SHOWEDTHEEXACTLOCATION",

        # Template 5: Nihilistic ending
        "THEREISNOTHINGLEFTBU" + "EASTNORTHEAST" +
        "ANDTHEOLDWALLREMINDSO" + "FTHE" +
        "BERLINCLOCK" + "ANDITISNOLONGERTHEREX",

        # Template 6: Coordinates
        "LAYERTWOOFTHECODESGO" + "EASTNORTHEAST" +
        "ATTHIRTYDEGREESFIFTY" + "ATTHE" +
        "BERLINCLOCK" + "INTHEALEXANDERPLATZEX",
    ]

    for i, template in enumerate(templates):
        # Pad or trim to 97
        pt = template[:CT_LEN].ljust(CT_LEN, 'X')

        # Verify crib alignment
        crib_ok = True
        for pos, ch in CRIB_DICT.items():
            if pt[pos] != ch:
                crib_ok = False
                break

        if not crib_ok:
            # Adjust: force cribs
            pt_list = list(pt)
            for pos, ch in CRIB_DICT.items():
                pt_list[pos] = ch
            pt = ''.join(pt_list)

        for variant in ["vig", "beau"]:
            keys = compute_key(pt, 0, variant)

            bean = check_bean(keys)

            # Check periodicity
            periodic_at = []
            for period in range(2, 50):
                if check_periodicity(keys, period):
                    periodic_at.append(period)

            # Check if key is readable
            key_text = ''.join(ALPH[keys[p]] for p in sorted(keys.keys()))

            # Count vowels in key
            vowels = sum(1 for c in key_text if c in 'AEIOU')
            vowel_pct = vowels / len(key_text) if key_text else 0

            # Compute IC of key
            from collections import Counter
            freq = Counter(key_text)
            n = len(key_text)
            ic = sum(f * (f-1) for f in freq.values()) / (n * (n-1)) if n > 1 else 0

            if bean or periodic_at or vowel_pct > 0.30:
                print(f"\n  Template {i+1} ({variant}):")
                print(f"    PT: {pt[:50]}...")
                print(f"    Key: {key_text[:50]}...")
                print(f"    Bean: {'PASS' if bean else 'FAIL'}")
                print(f"    Periodic at: {periodic_at[:10]}")
                print(f"    Key vowel%: {vowel_pct:.0%}")
                print(f"    Key IC: {ic:.4f}")

    return {}


def main():
    print(f"E-SOLVE-06: Crib Dragging and Plaintext Hypothesis Testing")
    print(f"CT: {CT[:45]}...")

    t0 = time.time()

    r1 = test_crib_extensions()
    r2 = test_word_crib_drag()
    r3 = test_full_pt_hypotheses()

    elapsed = time.time() - t0
    print(f"\n{'=' * 70}")
    print(f"E-SOLVE-06 COMPLETE ({elapsed:.1f}s)")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
