#!/usr/bin/env python3
"""Test autokey and non-periodic ciphers on 73-char column mask extracts.

The 28x31 native grid has a 9-column crib-free band (cols 8-16).
Removing 8 of 9 columns gives exactly 24 nulls, producing a 73-char extract.
The cribs shift to positions 13-25 (ENE) and 47-57 (BC) in all 9 variants.

GENUINELY UNTESTED: Autokey was only tested on raw 97-char text.
The 73-char column extract has different CT and shifted crib positions,
making it a fundamentally different test. CT-autokey key feedback changes
entirely because the CT itself is different.

Cipher: autokey, progressive, running-key, CT-feedback
Family: grille
Status: active
Keyspace: ~500K configs
Last run: never
Best score: N/A
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, MOD, CRIB_WORDS
from kryptos.kernel.transforms.autokey import autokey_decrypt

# ── Column mask extraction ──────────────────────────────────────────────

def extract_73(ct97: str, keep_col: int) -> tuple[str, list[int]]:
    """Extract 73 chars from 97 by removing 8 of 9 cols from band 8-16.

    Grid layout (K4 in 28x31 grid):
      Row 24: cols 27-30 → positions 0-3 (4 chars)
      Row 25: cols 0-30  → positions 4-34 (31 chars)
      Row 26: cols 0-30  → positions 35-65 (31 chars)
      Row 27: cols 0-30  → positions 66-96 (31 chars)

    Null band cols 8-16 in rows 25-27:
      Row 25: positions 12-20 (col = pos - 4)
      Row 26: positions 43-51 (col = pos - 35)
      Row 27: positions 74-82 (col = pos - 66)

    Returns (extracted_ct, original_positions).
    """
    assert 8 <= keep_col <= 16
    # Null positions in each row's band
    row25_band = set(range(12, 21))  # positions 12-20 = cols 8-16
    row26_band = set(range(43, 52))  # positions 43-51
    row27_band = set(range(74, 83))  # positions 74-82

    # Keep one position per row (the kept column)
    keep_pos = {4 + keep_col, 35 + keep_col, 66 + keep_col}

    # Null positions = band minus kept
    nulls = (row25_band | row26_band | row27_band) - keep_pos
    assert len(nulls) == 24, f"Expected 24 nulls, got {len(nulls)}"

    kept = []
    for i in range(len(ct97)):
        if i not in nulls:
            kept.append(i)
    assert len(kept) == 73, f"Expected 73 kept, got {len(kept)}"

    extracted = ''.join(ct97[i] for i in kept)
    return extracted, kept


def shifted_crib_positions() -> list[tuple[int, str]]:
    """Compute crib positions in the 73-char extract.

    All 9 column variants produce the same shifted positions because
    exactly 8 nulls fall before position 21, and exactly 16 before position 63.
    """
    # ENE: original 21-33, shift left by 8 → 13-25
    # BC:  original 63-73, shift left by 16 → 47-57
    cribs = []
    for orig_start, word in CRIB_WORDS:
        if orig_start == 21:
            shift = 8
        elif orig_start == 63:
            shift = 16
        else:
            raise ValueError(f"Unknown crib start: {orig_start}")
        for i, ch in enumerate(word):
            cribs.append((orig_start + i - shift, ch))
    return cribs


def score_against_cribs(plaintext: str, crib_pairs: list[tuple[int, str]]) -> int:
    """Count how many crib positions match."""
    hits = 0
    for pos, expected in crib_pairs:
        if 0 <= pos < len(plaintext) and plaintext[pos] == expected:
            hits += 1
    return hits


# ── CT-autokey (key from ciphertext, not plaintext) ─────────────────────

def ct_autokey_decrypt(ct: str, primer: str, variant: str = "vigenere") -> str:
    """CT-autokey: key[i] = primer[i] for i < len(primer), else CT[i-len(primer)].

    Unlike PT-autokey, the key stream is fully determined by CT + primer
    (no recursive dependency). This is a different cipher than standard autokey.
    """
    ct = ct.upper()
    primer = primer.upper()
    plen = len(primer)
    result = []

    for i, c_ch in enumerate(ct):
        c = ord(c_ch) - 65
        if i < plen:
            k = ord(primer[i]) - 65
        else:
            k = ord(ct[i - plen]) - 65  # KEY FROM CT, not PT

        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        result.append(chr(p + 65))
    return "".join(result)


# ── Progressive key cipher ──────────────────────────────────────────────

def progressive_decrypt(ct: str, a: int, b: int, variant: str = "vigenere") -> str:
    """Decrypt with linearly progressing key: key[i] = (a + b*i) mod 26."""
    result = []
    for i, c_ch in enumerate(ct):
        c = ord(c_ch) - 65
        k = (a + b * i) % MOD

        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        result.append(chr(p + 65))
    return "".join(result)


# ── Running key from reversed/shifted CT ────────────────────────────────

def running_key_decrypt(ct: str, key_text: str, variant: str = "vigenere") -> str:
    """Decrypt using a running key text (must be >= len(ct))."""
    result = []
    for i, c_ch in enumerate(ct):
        c = ord(c_ch) - 65
        k = ord(key_text[i % len(key_text)]) - 65

        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        result.append(chr(p + 65))
    return "".join(result)


# ── KA-alphabet variants ────────────────────────────────────────────────

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}


def ka_autokey_decrypt(ct: str, primer: str, variant: str = "vigenere",
                       ct_feedback: bool = False) -> str:
    """Autokey using KA alphabet indexing instead of standard A=0 B=1."""
    ct = ct.upper()
    primer = primer.upper()
    plen = len(primer)
    result = []

    for i, c_ch in enumerate(ct):
        c = KA_IDX[c_ch]
        if i < plen:
            k = KA_IDX[primer[i]]
        elif ct_feedback:
            k = KA_IDX[ct[i - plen]]
        else:
            k = KA_IDX[result[i - plen]]

        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        result.append(KA[p])
    return "".join(result)


# ── Main ────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("COLUMN MASK AUTOKEY & NON-PERIODIC CIPHER TEST")
    print("=" * 70)

    crib_pairs = shifted_crib_positions()
    print(f"\nShifted crib positions in 73-char extract:")
    ene_shifted = [(p, c) for p, c in crib_pairs if p <= 25]
    bc_shifted = [(p, c) for p, c in crib_pairs if p >= 47]
    print(f"  ENE: positions {ene_shifted[0][0]}-{ene_shifted[-1][0]}")
    print(f"  BC:  positions {bc_shifted[0][0]}-{bc_shifted[-1][0]}")

    # Top keywords for primers
    KEYWORDS = [
        "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
        "BERLIN", "CLOCK", "PALIMPSEST", "SANBORN", "SCHEIDT",
        "LANGLEY", "ANTIPODES", "LOOMIS", "GRILLE", "CARDAN",
        "ENIGMA", "CIPHER", "POINT", "COMPASS", "NORTH",
        "EAST", "FIVE", "SHADOW", "LIGHT", "WELTZEITUHR",
    ]

    # Single-letter primers
    SINGLE = [chr(i + 65) for i in range(26)]

    variants = ["vigenere", "beaufort", "var_beaufort"]
    best_overall = 0
    best_configs = []
    total_configs = 0

    # Test all 9 column-keep variants
    for keep_col in range(8, 17):
        ct73, orig_pos = extract_73(CT, keep_col)

        # Verify cribs are at expected positions
        for pos, expected_ch in crib_pairs:
            orig_p = orig_pos[pos]
            assert CT[orig_p] == ct73[pos], \
                f"Position mismatch: ct73[{pos}]={ct73[pos]} != CT[{orig_p}]={CT[orig_p]}"

        if keep_col == 8:
            print(f"\n73-char extract (keep col {keep_col}): {ct73}")
            print(f"Length: {len(ct73)}")
            # Show what chars differ between col-keep variants
            print(f"\nChars at kept positions (vary across 9 variants):")
            for kc in range(8, 17):
                ct73_v, _ = extract_73(CT, kc)
                diff_chars = f"  col {kc:2d}: pos12={ct73_v[12]} pos35={ct73_v[35]} pos58={ct73_v[58]}"
                print(diff_chars)

        # ── Test 1: Standard PT-autokey (from kernel) ────────────────────
        for variant in variants:
            for primer in SINGLE + KEYWORDS:
                try:
                    pt = autokey_decrypt(ct73, primer, variant)
                    score = score_against_cribs(pt, crib_pairs)
                    total_configs += 1
                    if score > best_overall:
                        best_overall = score
                        best_configs = []
                    if score >= best_overall and score >= 4:
                        best_configs.append(
                            (score, f"PT-autokey/{variant}/AZ primer={primer} col={keep_col}",
                             pt[:30]))
                except Exception:
                    pass

        # ── Test 2: CT-autokey (key from ciphertext) ─────────────────────
        for variant in variants:
            for primer in SINGLE + KEYWORDS:
                try:
                    pt = ct_autokey_decrypt(ct73, primer, variant)
                    score = score_against_cribs(pt, crib_pairs)
                    total_configs += 1
                    if score > best_overall:
                        best_overall = score
                        best_configs = []
                    if score >= best_overall and score >= 4:
                        best_configs.append(
                            (score, f"CT-autokey/{variant}/AZ primer={primer} col={keep_col}",
                             pt[:30]))
                except Exception:
                    pass

        # ── Test 3: KA-alphabet autokey (PT and CT feedback) ─────────────
        for ct_fb in [False, True]:
            fb_label = "CT" if ct_fb else "PT"
            for variant in variants:
                for primer in SINGLE + KEYWORDS:
                    try:
                        pt = ka_autokey_decrypt(ct73, primer, variant, ct_feedback=ct_fb)
                        score = score_against_cribs(pt, crib_pairs)
                        total_configs += 1
                        if score > best_overall:
                            best_overall = score
                            best_configs = []
                        if score >= best_overall and score >= 4:
                            best_configs.append(
                                (score, f"KA-{fb_label}-autokey/{variant} primer={primer} col={keep_col}",
                                 pt[:30]))
                    except Exception:
                        pass

        # ── Test 4: Progressive key ──────────────────────────────────────
        for variant in variants:
            for a in range(26):
                for b in range(26):
                    pt = progressive_decrypt(ct73, a, b, variant)
                    score = score_against_cribs(pt, crib_pairs)
                    total_configs += 1
                    if score > best_overall:
                        best_overall = score
                        best_configs = []
                    if score >= best_overall and score >= 4:
                        best_configs.append(
                            (score, f"Progressive/{variant} a={a} b={b} col={keep_col}",
                             pt[:30]))

        # ── Test 5: Running key from CT itself ───────────────────────────
        running_keys = {
            "CT73_reversed": ct73[::-1],
            "CT97_reversed": CT[::-1],
            "CT97_itself": CT,
        }
        # Also try Caesar-shifted CT as running key
        for shift in range(1, 26):
            shifted = ''.join(chr((ord(c) - 65 + shift) % 26 + 65) for c in ct73)
            running_keys[f"CT73_shift{shift}"] = shifted

        for key_name, key_text in running_keys.items():
            for variant in variants:
                pt = running_key_decrypt(ct73, key_text, variant)
                score = score_against_cribs(pt, crib_pairs)
                total_configs += 1
                if score > best_overall:
                    best_overall = score
                    best_configs = []
                if score >= best_overall and score >= 4:
                    best_configs.append(
                        (score, f"Running/{variant}/{key_name} col={keep_col}",
                         pt[:30]))

        # ── Test 6: Longer autokey primers (2-13 chars from keywords) ────
        for variant in variants:
            for word in KEYWORDS:
                for plen in range(2, min(14, len(word) + 1)):
                    primer = word[:plen]
                    # PT-autokey
                    try:
                        pt = autokey_decrypt(ct73, primer, variant)
                        score = score_against_cribs(pt, crib_pairs)
                        total_configs += 1
                        if score > best_overall:
                            best_overall = score
                            best_configs = []
                        if score >= best_overall and score >= 4:
                            best_configs.append(
                                (score, f"PT-autokey/{variant}/AZ primer={primer} col={keep_col}",
                                 pt[:30]))
                    except Exception:
                        pass
                    # CT-autokey
                    try:
                        pt = ct_autokey_decrypt(ct73, primer, variant)
                        score = score_against_cribs(pt, crib_pairs)
                        total_configs += 1
                        if score > best_overall:
                            best_overall = score
                            best_configs = []
                        if score >= best_overall and score >= 4:
                            best_configs.append(
                                (score, f"CT-autokey/{variant}/AZ primer={primer} col={keep_col}",
                                 pt[:30]))
                    except Exception:
                        pass

        # ── Test 7: Autokey with offset feedback ─────────────────────────
        # key[i] = CT[i-d] or PT[i-d] for d = 1..20 (not just d = primer_len)
        for variant in variants:
            for d in range(1, 21):
                for start_key in range(26):  # single-char start
                    # CT-feedback with offset d
                    pt_chars = []
                    for i in range(len(ct73)):
                        c = ord(ct73[i]) - 65
                        if i < d:
                            k = start_key
                        else:
                            k = ord(ct73[i - d]) - 65

                        if variant == "vigenere":
                            p = (c - k) % MOD
                        elif variant == "beaufort":
                            p = (k - c) % MOD
                        elif variant == "var_beaufort":
                            p = (c + k) % MOD
                        pt_chars.append(chr(p + 65))

                    pt = ''.join(pt_chars)
                    score = score_against_cribs(pt, crib_pairs)
                    total_configs += 1
                    if score > best_overall:
                        best_overall = score
                        best_configs = []
                    if score >= best_overall and score >= 4:
                        best_configs.append(
                            (score, f"CT-offset-d{d}/{variant} start={chr(start_key+65)} col={keep_col}",
                             pt[:30]))

        # Progress report per column
        if keep_col == 8 or keep_col == 16:
            print(f"\n  [col {keep_col}] {total_configs:,} configs tested, best so far: {best_overall}/24")

    # ── Final report ─────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"RESULTS: {total_configs:,} total configs tested")
    print(f"Best score: {best_overall}/24")
    print(f"{'='*70}")

    if best_configs:
        # Deduplicate and sort
        seen = set()
        unique = []
        for score, desc, pt in sorted(best_configs, reverse=True):
            if desc not in seen:
                seen.add(desc)
                unique.append((score, desc, pt))
        for score, desc, pt in unique[:30]:
            print(f"  {score}/24  {desc}")
            print(f"         PT: {pt}...")
    else:
        print("  No configs scored >= 4/24")

    # ── Keystream analysis on 73-char extract ────────────────────────────
    print(f"\n{'='*70}")
    print("KEYSTREAM ANALYSIS (73-char extract, keep col 8)")
    print(f"{'='*70}")
    ct73, _ = extract_73(CT, 8)

    # Vigenère keystream at crib positions
    print("\nVigenère keystream (k = CT - PT mod 26):")
    vig_keys = []
    for pos, pt_ch in crib_pairs:
        ct_ch = ct73[pos]
        k = (ord(ct_ch) - ord(pt_ch)) % MOD
        vig_keys.append((pos, k, chr(k + 65)))

    print("  ENE (pos 13-25):", ' '.join(f"{k:2d}" for _, k, _ in vig_keys[:13]))
    print("              as:", ''.join(c for _, _, c in vig_keys[:13]))
    print("  BC  (pos 47-57):", ' '.join(f"{k:2d}" for _, k, _ in vig_keys[13:]))
    print("              as:", ''.join(c for _, _, c in vig_keys[13:]))

    # Check: do any positions mod p share same key?
    print("\nPeriod consistency check on 73-char positions:")
    for p in range(2, 25):
        buckets: dict[int, set[int]] = {}
        for pos, k, _ in vig_keys:
            r = pos % p
            if r not in buckets:
                buckets[r] = set()
            buckets[r].add(k)
        conflicts = sum(1 for s in buckets.values() if len(s) > 1)
        if conflicts == 0:
            print(f"  Period {p:2d}: CONSISTENT (0 conflicts) ← CHECK THIS")
        elif p <= 7:
            print(f"  Period {p:2d}: {conflicts} conflict(s)")

    # Frequency analysis
    print("\nFrequency analysis of 73-char extract (keep col 8):")
    freq = {}
    for c in ct73:
        freq[c] = freq.get(c, 0) + 1
    for c in sorted(freq, key=freq.get, reverse=True)[:10]:
        bar = '#' * freq[c]
        print(f"  {c}: {freq[c]:2d} ({freq[c]/73:.3f}) {bar}")

    # IC of 73-char extract
    n = len(ct73)
    ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
    print(f"\n  IC = {ic:.4f} (random={1/26:.4f}, English={0.0667:.4f})")

    print(f"\n{'='*70}")
    print("INTERPRETATION:")
    if best_overall <= 6:
        print("  ALL NOISE. No autokey, progressive, or running-key cipher")
        print("  on the 73-char column mask extract produces crib hits.")
        print("  Either the null mask model is wrong, or the cipher is")
        print("  something genuinely novel (custom tableau, multi-step,")
        print("  or transposition precedes substitution).")
    elif best_overall <= 9:
        print(f"  Best {best_overall}/24 = binomial noise territory.")
        print("  No actionable signal found.")
    else:
        print(f"  SIGNAL at {best_overall}/24! Investigate further.")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
