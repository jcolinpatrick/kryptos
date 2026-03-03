"""E-ATBASH-01: Atbash hypothesis — the carved K4 is Atbash of the real CT.

Hypothesis: PT -> simple substitution -> REAL CT -> Atbash -> carved text.
So REAL CT = Atbash(carved text).

Tests:
1. Vigenere/Beaufort/VarBeau decryption of Atbash CT with known keywords + A-Z
2. Key recovery at original crib positions (21-33, 63-73) in the Atbash CT
3. Sliding crib placement at every position to find consistent/repeating keys
"""
from __future__ import annotations

import sys
import os

# Ensure clean import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_WORDS, CRIB_DICT, N_CRIBS,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, recover_key_at_positions,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)


# ── Atbash transform ────────────────────────────────────────────────────────

def atbash(text: str) -> str:
    """Atbash: A<->Z, B<->Y, C<->X, etc."""
    return "".join(chr(155 - ord(c)) for c in text.upper())
    # 155 = ord('A') + ord('Z') = 65 + 90


# ── Common English words for detection ───────────────────────────────────────

COMMON_WORDS = {
    # 4-letter
    "THAT", "THIS", "WITH", "HAVE", "FROM", "THEY", "BEEN", "SOME",
    "THEM", "THAN", "EACH", "MAKE", "LIKE", "LONG", "LOOK", "MANY",
    "SAID", "CAME", "WERE", "INTO", "ONLY", "OVER", "SUCH", "TIME",
    "VERY", "WHEN", "COME", "JUST", "KNOW", "TAKE", "WILL", "WHAT",
    "YOUR", "EAST", "WEST", "NEAR", "DOOR", "WALL", "OPEN", "DARK",
    "ROOM", "LAND", "KING", "TOMB", "DEAD", "GOLD", "CLAY", "SAND",
    "IRON", "HAND", "BODY", "HALF", "LEFT", "PART", "SIDE", "SLOW",
    "DOWN", "DEEP", "SEAL", "ARCH", "RUIN",
    # 5-letter
    "THERE", "THEIR", "ABOUT", "WOULD", "OTHER", "WHICH", "COULD",
    "AFTER", "WHERE", "THESE", "THOSE", "UNDER", "LAYER", "NORTH",
    "SOUTH", "CLOCK", "LIGHT", "NIGHT", "STONE", "EARTH", "WATER",
    "FOUND", "SHAFT", "ENTRY", "DEATH", "GRAVE", "POINT", "PLACE",
    "SIGHT", "RUINS", "SCENE", "FLOOR", "INNER", "OUTER", "UPPER",
    "LOWER", "YEARS", "BUILT", "STOOD",
    # 6-letter
    "SHOULD", "BEFORE", "BERLIN", "SLOWLY", "GROUND", "BURIED",
    "TEMPLE", "SECRET", "HIDDEN", "WITHIN", "SHADOW", "TUNNEL",
    "COLUMN", "STATUE", "DESERT", "REMOVE", "OPENED", "BROKEN",
    "SUNKEN", "RISING", "FADING", "EMERGE", "REVEAL", "PHARAO",
    "ALMOST", "BARELY", "SEEMED", "BEYOND",
    # 7+ letter
    "BETWEEN", "THROUGH", "HOWEVER", "ANOTHER", "ALREADY",
    "NOTHING", "BECAUSE", "BENEATH", "WITHOUT", "PASSAGE",
    "CHAMBER", "ANCIENT", "PYRAMID", "LANTERN", "ENDLESS",
    "DESPERATELY", "INVISIBLE", "IQLUSION", "LANGLEY",
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "UNDERGRUUND",
    "NORTHEAST", "EASTNORTHEAST", "BERLINCLOCK",
    "SLIGHTLY", "DESERTED", "INTERIOR", "SOUTHERN",
    "NORTHERN", "SILENTLY", "DARKNESS",
}


def find_words_in_text(text: str) -> list[str]:
    """Find all common English words (4+ chars) that appear as substrings."""
    text = text.upper()
    found = []
    for word in sorted(COMMON_WORDS, key=len, reverse=True):
        if word in text:
            found.append(word)
    return found


def key_to_letters(key_vals: list[int]) -> str:
    """Convert numeric key values to letters."""
    return "".join(ALPH[k] for k in key_vals)


def check_key_periodicity(key_dict: dict[int, int]) -> list[tuple[int, int, str]]:
    """Check if key values at known positions show periodicity.

    Returns list of (period, matches, key_fragment) for periods with good matches.
    """
    positions = sorted(key_dict.keys())
    results = []

    for period in range(1, 30):
        # Group positions by residue mod period
        residues: dict[int, list[int]] = {}
        for pos in positions:
            r = pos % period
            residues.setdefault(r, [])
            residues[r].append(key_dict[pos])

        # Check consistency within each residue class
        total = 0
        consistent = 0
        for r, vals in residues.items():
            if len(vals) > 1:
                for i in range(1, len(vals)):
                    total += 1
                    if vals[i] == vals[0]:
                        consistent += 1

        if total > 0:
            results.append((period, consistent, total))

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80)
    print("E-ATBASH-01: Atbash Hypothesis — Keyword Decryption of Atbash(K4)")
    print("=" * 80)

    # ── Step 0: Compute Atbash CT ────────────────────────────────────────────
    atbash_ct = atbash(CT)
    print(f"\nOriginal carved K4:  {CT}")
    print(f"Atbash of K4:        {atbash_ct}")
    print(f"Length: {len(atbash_ct)}")

    # Verify Atbash is involutory
    assert atbash(atbash_ct) == CT, "Atbash is not involutory!"
    print("Verified: Atbash(Atbash(K4)) == K4")

    # Letter frequency comparison
    print(f"\nOriginal CT letter freqs: ", end="")
    for c in ALPH:
        cnt = CT.count(c)
        if cnt > 0:
            print(f"{c}:{cnt}", end=" ")
    print()
    print(f"Atbash CT letter freqs:  ", end="")
    for c in ALPH:
        cnt = atbash_ct.count(c)
        if cnt > 0:
            print(f"{c}:{cnt}", end=" ")
    print()

    # IC of Atbash CT (same as original since Atbash is monoalphabetic)
    freq = [atbash_ct.count(c) for c in ALPH]
    ic = sum(f * (f - 1) for f in freq) / (CT_LEN * (CT_LEN - 1))
    print(f"IC of Atbash CT: {ic:.4f} (should equal original: same under monoalphabetic)")

    # ══════════════════════════════════════════════════════════════════════════
    # PART 1: Keyword decryption (Vig / Beau / VarBeau)
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("PART 1: Keyword Decryption of Atbash CT")
    print("=" * 80)

    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]

    # Also add single letters A-Z
    single_letters = [chr(65 + i) for i in range(26)]

    variants = [
        CipherVariant.VIGENERE,
        CipherVariant.BEAUFORT,
        CipherVariant.VAR_BEAUFORT,
    ]

    best_hits: list[tuple[int, str, str, str, list[str]]] = []

    for variant in variants:
        print(f"\n--- {variant.value.upper()} ---")

        for kw_name in keywords + single_letters:
            key_nums = [ALPH_IDX[c] for c in kw_name]
            pt = decrypt_text(atbash_ct, key_nums, variant)
            words = find_words_in_text(pt)

            if len(kw_name) <= 1:
                label = f"key={kw_name}({ALPH_IDX[kw_name]:2d})"
            else:
                label = f"key={kw_name}"

            if words:
                print(f"  {label:25s} -> {pt}")
                print(f"  {'':25s}    WORDS FOUND: {', '.join(words)}")
                best_hits.append((len(words), variant.value, kw_name, pt, words))
            # For named keywords, always print output
            elif kw_name in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                print(f"  {label:25s} -> {pt}")
                print(f"  {'':25s}    (no common words found)")

    # Sort best hits
    if best_hits:
        print(f"\n--- TOP KEYWORD HITS (sorted by word count) ---")
        best_hits.sort(key=lambda x: -x[0])
        for count, var, kw, pt, words in best_hits[:20]:
            print(f"  [{count} words] {var:15s} key={kw:15s} -> {pt}")
            print(f"  {'':10s} Words: {', '.join(words)}")
    else:
        print("\nNo common English words found in any keyword decryption.")

    # ══════════════════════════════════════════════════════════════════════════
    # PART 2: Key recovery at original crib positions in the Atbash CT
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("PART 2: Key Recovery at Original Crib Positions (21-33, 63-73)")
    print("=" * 80)

    print(f"\nAtbash CT at crib positions:")
    print(f"  Pos 21-33: {''.join(atbash_ct[i] for i in range(21, 34))}")
    print(f"  Pos 63-73: {''.join(atbash_ct[i] for i in range(63, 74))}")
    print(f"  Original:  {''.join(CT[i] for i in range(21, 34))}")
    print(f"  Orig 63-73: {''.join(CT[i] for i in range(63, 74))}")

    recover_fns = {
        "Vigenere":      vig_recover_key,
        "Beaufort":      beau_recover_key,
        "Var_Beaufort":  varbeau_recover_key,
    }

    for var_name, recover_fn in recover_fns.items():
        print(f"\n  --- {var_name} key recovery ---")
        key_vals = {}
        for pos, pt_ch in CRIB_DICT.items():
            c = ALPH_IDX[atbash_ct[pos]]
            p = ALPH_IDX[pt_ch]
            k = recover_fn(c, p)
            key_vals[pos] = k

        # Show key at ENE positions
        ene_keys = [key_vals[i] for i in range(21, 34)]
        bc_keys = [key_vals[i] for i in range(63, 74)]
        print(f"    ENE (pos 21-33): {ene_keys} = {key_to_letters(ene_keys)}")
        print(f"    BC  (pos 63-73): {bc_keys} = {key_to_letters(bc_keys)}")

        # Check periodicity
        periods = check_key_periodicity(key_vals)
        best_periods = [(p, c, t) for p, c, t in periods if t > 0 and c / t > 0.3]
        best_periods.sort(key=lambda x: -x[1] / x[2])
        if best_periods:
            print(f"    Best periodicities: ", end="")
            for p, c, t in best_periods[:5]:
                print(f"period={p}({c}/{t}={c/t:.2f}) ", end="")
            print()

        # Check if key is all the same value (Caesar)
        unique_keys = set(key_vals.values())
        if len(unique_keys) == 1:
            val = list(unique_keys)[0]
            print(f"    *** CAESAR KEY: all positions map to {val} = {ALPH[val]} ***")

        # Check Bean equality: k[27] == k[65]
        if 27 in key_vals and 65 in key_vals:
            if key_vals[27] == key_vals[65]:
                print(f"    Bean EQ: k[27]={key_vals[27]}({ALPH[key_vals[27]]}) == k[65]={key_vals[65]}({ALPH[key_vals[65]]}) PASS")
            else:
                print(f"    Bean EQ: k[27]={key_vals[27]}({ALPH[key_vals[27]]}) != k[65]={key_vals[65]}({ALPH[key_vals[65]]}) FAIL")

    # ══════════════════════════════════════════════════════════════════════════
    # PART 3: Sliding crib — place cribs at every possible position
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("PART 3: Sliding Crib Placement — EASTNORTHEAST at all positions")
    print("=" * 80)

    crib_ene = "EASTNORTHEAST"
    crib_bc = "BERLINCLOCK"

    for var_name, recover_fn in recover_fns.items():
        print(f"\n--- {var_name} ---")
        best_slide: list[tuple[float, int, str, list[int]]] = []

        for start in range(CT_LEN - len(crib_ene) + 1):
            key_vals = []
            for i, ch in enumerate(crib_ene):
                pos = start + i
                c = ALPH_IDX[atbash_ct[pos]]
                p = ALPH_IDX[ch]
                k = recover_fn(c, p)
                key_vals.append(k)

            # Check for repeating patterns
            key_str = key_to_letters(key_vals)

            # Score: count of most-frequent key value / total
            from collections import Counter
            counts = Counter(key_vals)
            most_common_count = counts.most_common(1)[0][1]
            unique_count = len(set(key_vals))

            # Also check for periodic repetition
            best_period_score = 0
            best_period = 0
            for period in range(1, 8):
                matches = 0
                total = 0
                for j in range(len(key_vals)):
                    if j >= period:
                        total += 1
                        if key_vals[j] == key_vals[j % period]:
                            matches += 1
                if total > 0:
                    score = matches / total
                    if score > best_period_score:
                        best_period_score = score
                        best_period = period

            best_slide.append((best_period_score, start, key_str, key_vals))

        # Sort by periodicity score
        best_slide.sort(key=lambda x: -x[0])
        print(f"  Top 10 positions by key periodicity:")
        for score, start, key_str, key_vals in best_slide[:10]:
            print(f"    pos={start:2d}  key={key_str}  period_score={score:.3f}  "
                  f"best_period={0}  unique={len(set(key_vals))}")

        # Also check for keyword matches
        target_keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
        for kw in target_keywords:
            for start in range(CT_LEN - len(crib_ene) + 1):
                key_vals = []
                for i, ch in enumerate(crib_ene):
                    pos = start + i
                    c = ALPH_IDX[atbash_ct[pos]]
                    p = ALPH_IDX[ch]
                    k = recover_fn(c, p)
                    key_vals.append(k)

                # Check if this matches the keyword pattern
                expected = [ALPH_IDX[kw[i % len(kw)]] for i in range(len(crib_ene))]
                # Offset might not align, try all offsets
                for offset in range(len(kw)):
                    expected_shifted = [ALPH_IDX[kw[(i + offset) % len(kw)]] for i in range(len(crib_ene))]
                    matches = sum(1 for a, b in zip(key_vals, expected_shifted) if a == b)
                    if matches >= 10:  # Strong match threshold
                        print(f"    *** KEYWORD MATCH: {kw} offset={offset} at pos={start}: "
                              f"{matches}/{len(crib_ene)} matches")
                        print(f"        key={key_to_letters(key_vals)} expected={key_to_letters(expected_shifted)}")

    # ══════════════════════════════════════════════════════════════════════════
    # PART 4: Sliding BOTH cribs — find positions where both produce same key
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("PART 4: Sliding BOTH Cribs — Find Joint Consistency")
    print("=" * 80)

    for var_name, recover_fn in recover_fns.items():
        print(f"\n--- {var_name} ---")
        best_joint: list[tuple[float, int, int, int, str]] = []

        for ene_start in range(CT_LEN - len(crib_ene) + 1):
            for bc_start in range(CT_LEN - len(crib_bc) + 1):
                # Skip if overlapping
                ene_end = ene_start + len(crib_ene) - 1
                bc_end = bc_start + len(crib_bc) - 1
                if not (ene_end < bc_start or bc_end < ene_start):
                    continue

                # Recover keys from both cribs
                all_key_vals: dict[int, int] = {}
                for i, ch in enumerate(crib_ene):
                    pos = ene_start + i
                    c = ALPH_IDX[atbash_ct[pos]]
                    p = ALPH_IDX[ch]
                    all_key_vals[pos] = recover_fn(c, p)

                for i, ch in enumerate(crib_bc):
                    pos = bc_start + i
                    c = ALPH_IDX[atbash_ct[pos]]
                    p = ALPH_IDX[ch]
                    all_key_vals[pos] = recover_fn(c, p)

                # Check periodicity for small periods
                for period in range(1, 11):
                    positions_by_residue: dict[int, list[int]] = {}
                    for pos, kval in all_key_vals.items():
                        r = pos % period
                        positions_by_residue.setdefault(r, [])
                        positions_by_residue[r].append(kval)

                    total_checks = 0
                    consistent = 0
                    for r, vals in positions_by_residue.items():
                        if len(vals) > 1:
                            ref = vals[0]
                            for v in vals[1:]:
                                total_checks += 1
                                if v == ref:
                                    consistent += 1

                    if total_checks > 0:
                        ratio = consistent / total_checks
                        if ratio >= 0.8 and total_checks >= 5:
                            key_fragment = ""
                            for r in range(period):
                                if r in positions_by_residue:
                                    key_fragment += ALPH[positions_by_residue[r][0]]
                                else:
                                    key_fragment += "?"
                            best_joint.append((ratio, ene_start, bc_start, period, key_fragment))

        # Sort and show top results
        best_joint.sort(key=lambda x: (-x[0], x[3]))
        if best_joint:
            print(f"  Top results (period consistency >= 80%, >= 5 checks):")
            seen = set()
            count = 0
            for ratio, es, bs, period, kfrag in best_joint:
                tag = (es, bs, period)
                if tag not in seen and count < 20:
                    seen.add(tag)
                    count += 1
                    print(f"    ENE@{es:2d} BC@{bs:2d} period={period:2d} "
                          f"consistency={ratio:.3f} key_fragment={kfrag}")
        else:
            print("  No joint placements with >= 80% periodicity found.")

    # ══════════════════════════════════════════════════════════════════════════
    # PART 5: Check if Atbash CT has any notable properties
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("PART 5: Atbash CT Properties")
    print("=" * 80)

    # Check for palindrome-like structure
    reversed_atbash = atbash_ct[::-1]
    match_count = sum(1 for a, b in zip(atbash_ct, reversed_atbash) if a == b)
    print(f"\n  Atbash CT vs reversed: {match_count}/{CT_LEN} positions match")

    # Check if Atbash CT = any rotation of original CT
    for shift in range(1, CT_LEN):
        rotated = CT[shift:] + CT[:shift]
        if rotated == atbash_ct:
            print(f"  Atbash CT = rotation of CT by {shift}!")

    # Position-by-position comparison: Atbash(CT[i]) vs CT[i]
    fixed_points = [(i, CT[i], atbash_ct[i]) for i in range(CT_LEN) if CT[i] == atbash_ct[i]]
    print(f"\n  Fixed points (CT[i] == Atbash(CT)[i]): {len(fixed_points)}")
    for pos, orig, ab in fixed_points:
        print(f"    pos={pos}: {orig}")

    # Check if Atbash swaps map to anything interesting with cribs
    print(f"\n  Atbash mapping of crib characters in CT:")
    for pos, pt_ch in sorted(CRIB_DICT.items()):
        ct_ch = CT[pos]
        atbash_ct_ch = atbash_ct[pos]
        atbash_pt_ch = atbash(pt_ch)
        print(f"    pos={pos:2d}: CT={ct_ch} -> Atbash(CT)={atbash_ct_ch}  "
              f"PT={pt_ch} -> Atbash(PT)={atbash_pt_ch}")

    # ══════════════════════════════════════════════════════════════════════════
    # PART 6: Try Vig/Beau/VarBeau with KRYPTOS-alphabet key recovery
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("PART 6: Key Recovery Using Kryptos Alphabet (KA)")
    print("=" * 80)

    from kryptos.kernel.constants import KRYPTOS_ALPHABET
    KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

    for var_name, recover_fn in recover_fns.items():
        print(f"\n  --- {var_name} (KA alphabet) ---")
        key_vals = {}
        for pos, pt_ch in CRIB_DICT.items():
            c = KA_IDX[atbash_ct[pos]]
            p = KA_IDX[pt_ch]
            k = recover_fn(c, p)
            key_vals[pos] = k

        ene_keys = [key_vals[i] for i in range(21, 34)]
        bc_keys = [key_vals[i] for i in range(63, 74)]
        ene_letters = "".join(KRYPTOS_ALPHABET[k] for k in ene_keys)
        bc_letters = "".join(KRYPTOS_ALPHABET[k] for k in bc_keys)
        print(f"    ENE (pos 21-33): {ene_keys} = {ene_letters}")
        print(f"    BC  (pos 63-73): {bc_keys} = {bc_letters}")

        # Bean EQ check
        if 27 in key_vals and 65 in key_vals:
            if key_vals[27] == key_vals[65]:
                print(f"    Bean EQ: k[27]={key_vals[27]}({KRYPTOS_ALPHABET[key_vals[27]]}) == "
                      f"k[65]={key_vals[65]}({KRYPTOS_ALPHABET[key_vals[65]]}) PASS")
            else:
                print(f"    Bean EQ: k[27]={key_vals[27]}({KRYPTOS_ALPHABET[key_vals[27]]}) != "
                      f"k[65]={key_vals[65]}({KRYPTOS_ALPHABET[key_vals[65]]}) FAIL")

    # ══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    if best_hits:
        print(f"\nTotal keyword decryptions with English words found: {len(best_hits)}")
        print(f"Best hit: [{best_hits[0][0]} words] {best_hits[0][1]} key={best_hits[0][2]}")
        print(f"  -> {best_hits[0][3]}")
        print(f"  Words: {', '.join(best_hits[0][4])}")
    else:
        print("\nNo English words found in any keyword decryption of Atbash CT.")

    print("\nDone. Atbash hypothesis tested across all variants and keywords.")


if __name__ == "__main__":
    main()
