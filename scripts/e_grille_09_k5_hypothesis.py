#!/usr/bin/env python3
"""
E-GRILLE-09: Test whether the Cardan grille extract IS K5 ciphertext.

HYPOTHESIS:
  The 106-char grille extract from the KA Vigenère Tableau contains K5.
  K5 is confirmed to be 97 chars. The extract is 106 chars (9 extra).
  Sanborn stated K5 shares "some coded words at the same positions" as K4.

TESTS:
  1. Extract 97-char subsets from the 106-char grille extract
  2. At K4's known crib positions (21-33, 63-73), try decryption with
     known keywords — do we get EASTNORTHEAST / BERLINCLOCK or related words?
  3. Check if CT letters at crib positions match between K4 and the extract
  4. Try all Vigenère/Beaufort decryptions of the extract itself
  5. Check if the "shared coded words" constraint holds under various decodings
"""

from __future__ import annotations
import json
import sys
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
K4_LEN = 97

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
GRILLE_LEN = 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Known K4 cribs (0-indexed)
CRIB_ENE = ("EASTNORTHEAST", 21, 33)  # positions 21-33 inclusive
CRIB_BC  = ("BERLINCLOCK",   63, 73)  # positions 63-73 inclusive

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA", "BURIED",
    "LAYER", "TWO", "IDBYROWS", "XLAYERTWO",
]

CRIBS = ["EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "BERLIN", "CLOCK",
         "NORTHEAST", "BURIED", "LAYER", "SHADOW", "LIGHT", "SLOWLY",
         "DESPERATELY", "IQLUSION", "UNDERGROUND"]

# Quadgrams
_QUADGRAMS: dict[str, float] | None = None

def _load_quadgrams() -> dict[str, float]:
    global _QUADGRAMS
    if _QUADGRAMS is not None:
        return _QUADGRAMS
    for p in [Path("data/english_quadgrams.json"), Path("../data/english_quadgrams.json")]:
        if p.exists():
            _QUADGRAMS = json.loads(p.read_text())
            return _QUADGRAMS
    _QUADGRAMS = {}
    return _QUADGRAMS

def score_text(text: str) -> float:
    qg = _load_quadgrams()
    if not qg:
        return 0.0
    s = text.upper()
    return sum(qg.get(s[i:i+4], -10.0) for i in range(len(s) - 3))


# ── Cipher functions ────────────────────────────────────────────────────────

def vig_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    return "".join(alpha[(alpha.index(c) - alpha.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))

def vig_encrypt(pt: str, key: str, alpha: str = AZ) -> str:
    return "".join(alpha[(alpha.index(c) + alpha.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(pt))

def beau_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    return "".join(alpha[(alpha.index(key[i % len(key)]) - alpha.index(c)) % 26]
                   for i, c in enumerate(ct))

def varbeau_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    return "".join(alpha[(alpha.index(c) - alpha.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))


# ── Helpers ─────────────────────────────────────────────────────────────────

def has_any_crib(text: str) -> list[tuple[str, int]]:
    found = []
    upper = text.upper()
    for crib in CRIBS:
        idx = upper.find(crib)
        if idx >= 0:
            found.append((crib, idx))
    return found


def implied_keystream(ct: str, pt: str, alpha: str = AZ) -> str:
    """K[i] = (CT[i] - PT[i]) mod 26"""
    return "".join(alpha[(alpha.index(ct[i]) - alpha.index(pt[i])) % 26]
                   for i in range(min(len(ct), len(pt))))


# ── Test 1: Direct comparison at crib positions ────────────────────────────

def test_crib_position_overlap():
    """Do the grille extract and K4 CT share the same letters at crib positions?"""
    print("=" * 70)
    print("TEST 1: Direct letter comparison at K4 crib positions")
    print("=" * 70)
    print()

    # K4 crib positions
    for crib_name, start, end in [CRIB_ENE, CRIB_BC]:
        k4_slice = K4_CT[start:end+1]
        print(f"  K4 CT [{start}:{end+1}] = {k4_slice}")

        # Compare with grille extract at same positions (for various 97-char subsets)
        for offset in range(GRILLE_LEN - K4_LEN + 1):  # 0 through 9
            ge_subset = GRILLE_EXTRACT[offset:offset + K4_LEN]
            ge_slice = ge_subset[start:end+1]
            matches = sum(1 for a, b in zip(k4_slice, ge_slice) if a == b)
            pct = matches / len(k4_slice) * 100
            marker = " *** INTERESTING" if matches > len(k4_slice) * 0.3 else ""
            print(f"    Grille[{offset}:{offset+K4_LEN}][{start}:{end+1}] = {ge_slice}  "
                  f"matches={matches}/{len(k4_slice)} ({pct:.0f}%){marker}")
        print()


# ── Test 2: Decrypt grille extract at crib positions ───────────────────────

def test_decrypt_at_crib_positions():
    """Try decrypting the grille extract at K4's crib positions with known keywords."""
    print("=" * 70)
    print("TEST 2: Decrypt grille extract at K4 crib positions")
    print("=" * 70)
    print(f"  Looking for: EASTNORTHEAST at pos 21-33, BERLINCLOCK at pos 63-73")
    print()

    results = []

    for offset in range(GRILLE_LEN - K4_LEN + 1):
        candidate_k5 = GRILLE_EXTRACT[offset:offset + K4_LEN]

        for key in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt),
                                                ("varbeau", varbeau_decrypt)]:
                    try:
                        pt = cipher_fn(candidate_k5, key, alpha)
                    except (ValueError, IndexError):
                        continue

                    # Check at K4's known crib positions
                    ene_pt = pt[21:34]
                    bc_pt = pt[63:74]

                    # Check if EASTNORTHEAST or BERLINCLOCK appears at expected positions
                    ene_match = sum(1 for a, b in zip(ene_pt, "EASTNORTHEAST") if a == b)
                    bc_match = sum(1 for a, b in zip(bc_pt, "BERLINCLOCK") if a == b)

                    # "Some coded words at the same positions" — partial match is interesting
                    if ene_match >= 4 or bc_match >= 4:
                        results.append({
                            "offset": offset,
                            "keyword": key,
                            "alphabet": alpha_name,
                            "cipher": cipher_name,
                            "ene_pt": ene_pt,
                            "ene_match": ene_match,
                            "bc_pt": bc_pt,
                            "bc_match": bc_match,
                            "full_pt": pt,
                        })

                    # Also check if the cribs appear ANYWHERE
                    crib_hits = has_any_crib(pt)
                    if crib_hits:
                        results.append({
                            "offset": offset,
                            "keyword": key,
                            "alphabet": alpha_name,
                            "cipher": cipher_name,
                            "crib_hits": crib_hits,
                            "full_pt": pt,
                            "ene_match": ene_match,
                            "bc_match": bc_match,
                        })

    if results:
        # Sort by best crib match
        results.sort(key=lambda r: -(r.get("ene_match", 0) + r.get("bc_match", 0)))
        print(f"  Found {len(results)} interesting results:")
        for r in results[:20]:
            print(f"    offset={r['offset']} {r['cipher']}/{r['alphabet']} key={r['keyword']}")
            if r.get("crib_hits"):
                print(f"      CRIB HITS: {r['crib_hits']}")
            print(f"      ENE pos: {r.get('ene_pt', '?')} ({r.get('ene_match', 0)}/13)")
            print(f"      BC  pos: {r.get('bc_pt', '?')} ({r.get('bc_match', 0)}/11)")
            print(f"      Full PT: {r['full_pt'][:50]}...")
            print()
    else:
        print("  No results with >= 4 crib position matches or any crib substring found.")
    print()
    return results


# ── Test 3: Keystream comparison ───────────────────────────────────────────

def test_keystream_comparison():
    """If K5 uses the same key as K4, the keystreams at shared crib positions should match."""
    print("=" * 70)
    print("TEST 3: Keystream comparison (K4 known keystream vs grille extract)")
    print("=" * 70)
    print()

    # K4's known keystream fragments (from ground truth)
    # K[21..33] = BLZCDCYYGCKAZ (for EASTNORTHEAST under Vigenère)
    # K[63..73] = MUYKLGKORNA (for BERLINCLOCK under Vigenère)
    k4_ks_ene = "BLZCDCYYGCKAZ"
    k4_ks_bc  = "MUYKLGKORNA"

    print("  K4 known keystream:")
    print(f"    K[21:34] = {k4_ks_ene}  (from EASTNORTHEAST)")
    print(f"    K[63:74] = {k4_ks_bc}  (from BERLINCLOCK)")
    print()

    # If K5 shares "coded words at the same positions", and K5 uses the same key,
    # then the keystream at those positions should be the same.
    # Check: K5_CT[i] - K5_PT[i] = K4_CT[i] - K4_PT[i] at shared positions.

    # If K5_PT has EASTNORTHEAST at 21-33 and BERLINCLOCK at 63-73:
    for offset in range(GRILLE_LEN - K4_LEN + 1):
        candidate_k5 = GRILLE_EXTRACT[offset:offset + K4_LEN]

        # Implied K5 keystream if PT is the same as K4's cribs at those positions
        k5_ks_ene = implied_keystream(candidate_k5[21:34], "EASTNORTHEAST")
        k5_ks_bc  = implied_keystream(candidate_k5[63:74], "BERLINCLOCK")

        ene_match = sum(1 for a, b in zip(k5_ks_ene, k4_ks_ene) if a == b)
        bc_match = sum(1 for a, b in zip(k5_ks_bc, k4_ks_bc) if a == b)

        print(f"  Offset {offset}: K5 CT = GRILLE[{offset}:{offset+97}]")
        print(f"    K5 implied KS[21:34] = {k5_ks_ene}  (match K4: {ene_match}/13)")
        print(f"    K5 implied KS[63:74] = {k5_ks_bc}  (match K4: {bc_match}/11)")

        if k5_ks_ene == k4_ks_ene:
            print(f"    *** EXACT KEYSTREAM MATCH on EASTNORTHEAST ***")
        if k5_ks_bc == k4_ks_bc:
            print(f"    *** EXACT KEYSTREAM MATCH on BERLINCLOCK ***")

        # Also test: what if "same coded words" means same CT letters (not same PT)?
        ct_ene_match = sum(1 for a, b in zip(candidate_k5[21:34], K4_CT[21:34]) if a == b)
        ct_bc_match = sum(1 for a, b in zip(candidate_k5[63:74], K4_CT[63:74]) if a == b)
        if ct_ene_match > 3 or ct_bc_match > 3:
            print(f"    CT letter overlap: ENE={ct_ene_match}/13, BC={ct_bc_match}/11")
        print()


# ── Test 4: Full decrypt of the 106-char extract ──────────────────────────

def test_full_extract_decrypt():
    """Try decrypting the full 106-char extract as its own ciphertext."""
    print("=" * 70)
    print("TEST 4: Full decrypt of 106-char grille extract")
    print("=" * 70)
    print()

    best_results = []

    for key in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt),
                                            ("varbeau", varbeau_decrypt)]:
                try:
                    pt = cipher_fn(GRILLE_EXTRACT, key, alpha)
                except (ValueError, IndexError):
                    continue

                sc = score_text(pt)
                crib_hits = has_any_crib(pt)

                best_results.append({
                    "keyword": key,
                    "alphabet": alpha_name,
                    "cipher": cipher_name,
                    "score": sc,
                    "crib_hits": crib_hits,
                    "plaintext": pt,
                })

    best_results.sort(key=lambda r: -r["score"])

    print("  Top 10 by quadgram score:")
    for r in best_results[:10]:
        cribs = f" CRIBS: {r['crib_hits']}" if r["crib_hits"] else ""
        print(f"    {r['cipher']}/{r['alphabet']} key={r['keyword']:<12} "
              f"score={r['score']:>8.1f}{cribs}")
        print(f"      PT: {r['plaintext'][:60]}...")

    crib_results = [r for r in best_results if r["crib_hits"]]
    if crib_results:
        print(f"\n  *** {len(crib_results)} RESULTS WITH CRIB HITS: ***")
        for r in crib_results:
            print(f"    {r['cipher']}/{r['alphabet']} key={r['keyword']}: {r['crib_hits']}")
            print(f"      PT: {r['plaintext']}")
    print()
    return best_results


# ── Test 5: "Same coded words at same positions" interpretations ──────────

def test_shared_coded_words():
    """
    Sanborn: K5 shares 'some coded words at the same positions' as K4.

    Interpretations:
    A) Same PLAINTEXT words at same positions (e.g., both have BERLINCLOCK at 63-73)
    B) Same CIPHERTEXT letters at same positions
    C) Same ENCRYPTED WORDS (CT fragments) at same positions — the cipher of the
       same PT word produces the same CT substring
    """
    print("=" * 70)
    print("TEST 5: 'Some coded words at the same positions' analysis")
    print("=" * 70)
    print()

    # Interpretation B: Same CT letters
    print("  Interpretation B: Same CT letters at same positions")
    print(f"  K4 CT:        {K4_CT}")
    for offset in range(GRILLE_LEN - K4_LEN + 1):
        candidate = GRILLE_EXTRACT[offset:offset + K4_LEN]
        matches = sum(1 for a, b in zip(K4_CT, candidate) if a == b)
        # Find runs of matching positions
        runs = []
        run_start = None
        for i in range(K4_LEN):
            if K4_CT[i] == candidate[i]:
                if run_start is None:
                    run_start = i
            else:
                if run_start is not None:
                    runs.append((run_start, i - 1, K4_CT[run_start:i]))
                    run_start = None
        if run_start is not None:
            runs.append((run_start, K4_LEN - 1, K4_CT[run_start:]))

        long_runs = [r for r in runs if r[1] - r[0] >= 1]  # runs of 2+
        print(f"    Offset {offset}: {matches}/{K4_LEN} letter matches "
              f"(expected random: ~{K4_LEN/26:.1f})")
        if long_runs:
            for start, end, text in long_runs:
                print(f"      Run [{start}-{end}]: '{text}'")
    print()

    # Interpretation C: Same encrypted fragments
    # If K4 and K5 use the same key but different PTs, then at positions where
    # PT4 = PT5, we'd have CT4 = CT5.
    # "Coded words" = CT fragments that are identical because the PT words are identical
    print("  Interpretation C: If K4 and K5 share some PT words at same positions,")
    print("  and use the same encryption key, their CT at those positions matches.")
    print("  → This IS Interpretation B. Shared CT = shared PT (under same key).")
    print()

    # Check: what K4 CT letters at crib positions tell us
    print("  K4 'coded words' (CT at crib positions):")
    print(f"    EASTNORTHEAST → CT[21:34] = {K4_CT[21:34]}")
    print(f"    BERLINCLOCK   → CT[63:74] = {K4_CT[63:74]}")
    print()
    print("  If K5 shares these 'coded words at the same positions',")
    print("  then K5_CT[21:34] should contain some/all of: {K4_CT[21:34]}")
    print(f"  and K5_CT[63:74] should contain some/all of: {K4_CT[63:74]}")
    print()

    for offset in range(GRILLE_LEN - K4_LEN + 1):
        candidate = GRILLE_EXTRACT[offset:offset + K4_LEN]
        ene_ct = candidate[21:34]
        bc_ct = candidate[63:74]
        ene_match = sum(1 for a, b in zip(ene_ct, K4_CT[21:34]) if a == b)
        bc_match = sum(1 for a, b in zip(bc_ct, K4_CT[63:74]) if a == b)
        print(f"    Offset {offset}: ENE ct={ene_ct} match={ene_match}/13 | "
              f"BC ct={bc_ct} match={bc_match}/11")


# ── Test 6: Statistical comparison ────────────────────────────────────────

def test_statistics():
    """Compare frequency distributions of K4 CT vs grille extract."""
    print()
    print("=" * 70)
    print("TEST 6: Statistical comparison — K4 CT vs Grille Extract")
    print("=" * 70)
    print()

    def freq(text):
        counts = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        return counts

    def ic(text):
        n = len(text)
        f = freq(text)
        return sum(c * (c - 1) for c in f.values()) / (n * (n - 1)) if n > 1 else 0

    k4_freq = freq(K4_CT)
    ge_freq = freq(GRILLE_EXTRACT)

    print(f"  K4 CT:  len={len(K4_CT)}, IC={ic(K4_CT):.4f}, unique={len(k4_freq)}")
    print(f"  Grille: len={len(GRILLE_EXTRACT)}, IC={ic(GRILLE_EXTRACT):.4f}, unique={len(ge_freq)}")
    print()

    # Letter distribution comparison
    print(f"  {'Letter':>6} {'K4':>4} {'Grille':>6}  {'Delta':>5}")
    print(f"  {'-'*6:>6} {'-'*4:>4} {'-'*6:>6}  {'-'*5:>5}")
    for c in AZ:
        k = k4_freq.get(c, 0)
        g = ge_freq.get(c, 0)
        delta = g - k
        marker = " <<<" if c == 'T' else ""
        print(f"  {c:>6} {k:>4} {g:>6}  {delta:>+5}{marker}")

    # Chi-squared-like comparison (rescaled)
    print()
    k4_total = len(K4_CT)
    ge_total = len(GRILLE_EXTRACT)
    chi2 = 0
    for c in AZ:
        k4_prop = k4_freq.get(c, 0) / k4_total
        ge_prop = ge_freq.get(c, 0) / ge_total
        if k4_prop > 0:
            chi2 += (ge_prop - k4_prop) ** 2 / k4_prop
    print(f"  Chi-squared (proportional): {chi2:.6f}")
    print(f"  (Lower = more similar distributions)")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    print()
    print("#" * 70)
    print("#  E-GRILLE-09: Is the Cardan Grille Extract actually K5?")
    print("#" * 70)
    print()
    print(f"  K4 CT ({K4_LEN} chars): {K4_CT}")
    print(f"  Grille ({GRILLE_LEN} chars): {GRILLE_EXTRACT}")
    print(f"  Grille missing: T")
    print(f"  K4 contains T: {'T' in K4_CT} (count: {K4_CT.count('T')})")
    print()

    _load_quadgrams()

    test_crib_position_overlap()
    results_2 = test_decrypt_at_crib_positions()
    test_keystream_comparison()
    results_4 = test_full_extract_decrypt()
    test_shared_coded_words()
    test_statistics()

    # ── Summary ────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    crib_found = any(r.get("crib_hits") for r in results_2)
    high_scores = [r for r in (results_4 or []) if r["score"] > -350]

    print(f"  Crib hits in positional decrypt: {'YES' if crib_found else 'NO'}")
    print(f"  High quadgram scores in full decrypt: {len(high_scores)}")

    if crib_found:
        print("\n  *** K5 HYPOTHESIS SHOWS PROMISE — investigate further ***")
    elif high_scores:
        print("\n  *** Some high scores — worth investigating ***")
    else:
        print("\n  K5 hypothesis shows no immediate signal from basic tests.")
        print("  Does NOT eliminate the hypothesis — K5 may use a different key")
        print("  or the 'shared coded words' may be a subset we haven't identified.")
    print()


if __name__ == "__main__":
    main()
