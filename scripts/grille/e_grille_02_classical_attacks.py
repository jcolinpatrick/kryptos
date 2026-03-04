#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRILLE-02: Classical cipher attacks on YAR grille CT.

The 106-character CT was extracted by reading Kryptos tableau characters
through a Cardan grille defined by Y/A/R positions in K4 ciphertext.

Attacks:
  1. Caesar shifts (A-Z)
  2. Caesar shifts (KA alphabet)
  3. Vigenere decrypt with candidate keys
  4. Beaufort decrypt with candidate keys
  5. Variant Beaufort decrypt with candidate keys
  6. Atbash
  7. Affine cipher (all valid a,b pairs)
  8. Reversed CT + Caesar
  9. Keyword-mixed alphabet (KRYPTOS) + Caesar
  10. Quadgram scoring of all outputs

Run: PYTHONPATH=src python3 -u scripts/e_grille_02_classical_attacks.py
"""

import json
import math
import os
import sys
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

YAR_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
YAR_LEN = len(YAR_CT)  # 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

CANDIDATE_KEYS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
    "EASTNORTHEAST", "SANBORN", "SCHEIDT", "YAR", "CARDAN",
    "GRILLE", "MASKEDLANGUAGE", "UNDERGROUND",
]

# Common English trigrams for quick scoring
COMMON_TRIGRAMS = {
    "THE", "AND", "ING", "ION", "TIO", "ENT", "FOR", "ATE",
    "HER", "TER", "HAT", "EST", "ERS", "HIS", "RES", "ALL",
    "INT", "VER", "STA", "NOT", "OUR", "ARE", "WAS", "ONE",
    "HAS", "HEN", "OUT", "ITH", "AVE", "STR", "ITS", "IST",
    "ERE", "COM", "PRO", "CON", "MAN", "ORT", "NDE", "OFT",
}

# Common English words (3+ chars) for word detection
COMMON_WORDS = {
    "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
    "CAN", "HER", "WAS", "ONE", "OUR", "OUT", "HAS", "HIS",
    "HOW", "ITS", "MAY", "NEW", "NOW", "OLD", "SEE", "WAY",
    "WHO", "DID", "GET", "LET", "SAY", "SHE", "TOO", "USE",
    "DAD", "MOM", "MAN", "DAY", "HAD", "HIM", "HIT", "TWO",
    "THAT", "WITH", "HAVE", "THIS", "WILL", "YOUR", "FROM",
    "THEY", "BEEN", "SAID", "EACH", "MAKE", "LIKE", "LONG",
    "LOOK", "MANY", "SOME", "THEM", "THAN", "TIME", "VERY",
    "WHEN", "COME", "MADE", "FIND", "BACK", "ONLY", "JUST",
    "OVER", "KNOW", "TAKE", "INTO", "YEAR", "MOST", "GOOD",
    "GIVE", "ALSO", "HELP", "TELL", "MORE", "HERE", "MUST",
    "HOME", "HAND", "HIGH", "KEEP", "LAST", "CITY", "AWAY",
    "WORK", "WHAT", "WERE", "WELL", "THEN", "THEM", "MUCH",
    "THESE", "THERE", "THEIR", "WHICH", "WOULD", "OTHER",
    "ABOUT", "AFTER", "COULD", "FIRST", "GREAT", "WHERE",
    "WORLD", "STILL", "THINK", "NEVER", "UNDER", "LIGHT",
    "EAST", "WEST", "NORTH", "SOUTH", "CLOCK", "BERLIN",
    "BETWEEN", "SHADOW", "SUBTLE", "SHADING", "ABSENCE",
    "UNDERGROUND", "PALIMPSEST", "KRYPTOS", "SECRET",
    "SLOWLY", "DESPERATELY", "REMAINS", "BURIED",
    "TOTAL", "DARKNESS", "EARTH", "THROUGH", "HIDDEN",
    "LAYER", "BELOW", "ABOVE", "WITHIN", "ANCIENT",
    "TOMB", "DEATH", "GOLD", "TEMPLE", "PHARAOH",
    "CARTER", "KING", "QUEEN", "MASK", "CIPHER",
    "CODE", "DECODE", "ENCRYPT", "DECRYPT",
}

# ── Quadgram Loader ──────────────────────────────────────────────────────────

QUADGRAMS = {}
QUADGRAM_FLOOR = -10.0  # penalty for missing quadgrams
TOTAL_QUADGRAMS = 0

def load_quadgrams():
    global QUADGRAMS, QUADGRAM_FLOOR, TOTAL_QUADGRAMS
    qpath = Path(__file__).resolve().parent.parent / "data" / "english_quadgrams.json"
    if not qpath.exists():
        print(f"[WARN] Quadgram file not found: {qpath}")
        return False
    with open(qpath) as f:
        raw = json.load(f)
    # raw is dict of quadgram -> log-probability (already log10)
    # Check if values are already log-probs or raw counts
    sample_val = next(iter(raw.values()))
    if sample_val < 0:
        # Already log-probabilities
        QUADGRAMS = raw
        QUADGRAM_FLOOR = min(raw.values()) - 1.0
    else:
        # Raw counts -> convert to log-probs
        TOTAL_QUADGRAMS = sum(raw.values())
        QUADGRAMS = {k: math.log10(v / TOTAL_QUADGRAMS) for k, v in raw.items()}
        QUADGRAM_FLOOR = math.log10(0.5 / TOTAL_QUADGRAMS)
    print(f"[INFO] Loaded {len(QUADGRAMS)} quadgrams, floor={QUADGRAM_FLOOR:.4f}")
    return True

def quadgram_score(text: str) -> float:
    """Return average log10 probability per quadgram."""
    text = text.upper()
    if len(text) < 4:
        return QUADGRAM_FLOOR
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QUADGRAM_FLOOR)
        count += 1
    return total / count if count > 0 else QUADGRAM_FLOOR

# ── Scoring ──────────────────────────────────────────────────────────────────

def trigram_count(text: str) -> int:
    """Count occurrences of common English trigrams."""
    text = text.upper()
    count = 0
    for i in range(len(text) - 2):
        if text[i:i+3] in COMMON_TRIGRAMS:
            count += 1
    return count

def word_count(text: str) -> list:
    """Find common English words (3+ chars) in text. Return list of (word, position)."""
    text = text.upper()
    found = []
    # Check all word lengths from longest to shortest
    for word in sorted(COMMON_WORDS, key=len, reverse=True):
        idx = 0
        while True:
            pos = text.find(word, idx)
            if pos == -1:
                break
            found.append((word, pos))
            idx = pos + 1
    return found

def combined_score(text: str) -> float:
    """Combined English-likeness score: trigrams + words + quadgrams."""
    tc = trigram_count(text)
    wc = len(word_count(text))
    qg = quadgram_score(text) if QUADGRAMS else -10.0
    # Normalize: trigrams worth 1pt each, words worth 3pt each, quadgram bonus
    # quadgram: English text ~= -2.5/char, random ~= -4.5/char
    qg_bonus = max(0, (qg + 4.5) * 10)  # 0 if random, ~20 if good English
    return tc + 3 * wc + qg_bonus

# ── Cipher Implementations ──────────────────────────────────────────────────

def caesar_shift_az(ct: str, shift: int) -> str:
    """Caesar decrypt: PT[i] = (CT[i] - shift) mod 26 in A-Z."""
    return "".join(AZ[(AZ_IDX[c] - shift) % 26] for c in ct)

def caesar_shift_ka(ct: str, shift: int) -> str:
    """Caesar decrypt: PT[i] = (CT[i] - shift) mod 26 in KA alphabet."""
    return "".join(KA[(KA_IDX[c] - shift) % 26] for c in ct)

def vigenere_decrypt(ct: str, key: str) -> str:
    """Vigenere decrypt: PT[i] = (CT[i] - KEY[i]) mod 26."""
    key_len = len(key)
    return "".join(
        AZ[(AZ_IDX[ct[i]] - AZ_IDX[key[i % key_len]]) % 26]
        for i in range(len(ct))
    )

def beaufort_decrypt(ct: str, key: str) -> str:
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26."""
    key_len = len(key)
    return "".join(
        AZ[(AZ_IDX[key[i % key_len]] - AZ_IDX[ct[i]]) % 26]
        for i in range(len(ct))
    )

def variant_beaufort_decrypt(ct: str, key: str) -> str:
    """Variant Beaufort decrypt: PT[i] = (CT[i] + KEY[i]) mod 26.
    (This is the Vigenere encrypt direction used as decrypt.)"""
    key_len = len(key)
    return "".join(
        AZ[(AZ_IDX[ct[i]] + AZ_IDX[key[i % key_len]]) % 26]
        for i in range(len(ct))
    )

def atbash(ct: str) -> str:
    """Atbash: A<->Z, B<->Y, etc."""
    return "".join(AZ[25 - AZ_IDX[c]] for c in ct)

def affine_decrypt(ct: str, a: int, b: int) -> str:
    """Affine decrypt: PT[i] = a_inv * (CT[i] - b) mod 26."""
    a_inv = pow(a, -1, 26)
    return "".join(AZ[(a_inv * (AZ_IDX[c] - b)) % 26] for c in ct)

def make_keyword_alphabet(keyword: str) -> str:
    """Create a keyword-mixed alphabet."""
    seen = set()
    result = []
    for c in keyword.upper():
        if c not in seen and c in AZ_IDX:
            result.append(c)
            seen.add(c)
    for c in AZ:
        if c not in seen:
            result.append(c)
            seen.add(c)
    return "".join(result)

def keyword_caesar_decrypt(ct: str, keyword_alpha: str, shift: int) -> str:
    """Substitute using keyword alphabet then Caesar shift."""
    ka_idx = {c: i for i, c in enumerate(keyword_alpha)}
    return "".join(AZ[(ka_idx[c] - shift) % 26] for c in ct)

# ── GCD for affine ──────────────────────────────────────────────────────────

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("E-GRILLE-02: Classical Cipher Attacks on YAR Grille CT")
    print("=" * 80)
    print(f"\nCT ({YAR_LEN} chars): {YAR_CT}\n")

    # Load quadgrams
    has_quadgrams = load_quadgrams()

    # Collect all results: (score, label, plaintext)
    all_results = []

    def record(label: str, pt: str):
        sc = combined_score(pt)
        all_results.append((sc, label, pt))

    # ── 1. Caesar shifts (A-Z) ───────────────────────────────────────────
    print("\n" + "=" * 70)
    print("1. CAESAR SHIFTS (A-Z alphabet)")
    print("=" * 70)
    for shift in range(26):
        pt = caesar_shift_az(YAR_CT, shift)
        sc = combined_score(pt)
        label = f"Caesar-AZ shift={shift}"
        record(label, pt)
        marker = " <<<" if sc > 15 else ""
        print(f"  shift={shift:2d}: {pt[:60]}...  (score={sc:.1f}){marker}")

    # ── 2. Caesar shifts (KA alphabet) ───────────────────────────────────
    print("\n" + "=" * 70)
    print("2. CAESAR SHIFTS (KA alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ)")
    print("=" * 70)
    for shift in range(26):
        pt = caesar_shift_ka(YAR_CT, shift)
        sc = combined_score(pt)
        label = f"Caesar-KA shift={shift}"
        record(label, pt)
        marker = " <<<" if sc > 15 else ""
        print(f"  shift={shift:2d}: {pt[:60]}...  (score={sc:.1f}){marker}")

    # ── 3. Vigenere decrypt with candidate keys ──────────────────────────
    print("\n" + "=" * 70)
    print("3. VIGENERE DECRYPT (PT = CT - KEY mod 26)")
    print("=" * 70)
    for key in CANDIDATE_KEYS:
        pt = vigenere_decrypt(YAR_CT, key)
        sc = combined_score(pt)
        label = f"Vigenere key={key}"
        record(label, pt)
        marker = " <<<" if sc > 15 else ""
        print(f"  key={key:20s}: {pt[:55]}...  (score={sc:.1f}){marker}")

    # ── 4. Beaufort decrypt with candidate keys ──────────────────────────
    print("\n" + "=" * 70)
    print("4. BEAUFORT DECRYPT (PT = KEY - CT mod 26)")
    print("=" * 70)
    for key in CANDIDATE_KEYS:
        pt = beaufort_decrypt(YAR_CT, key)
        sc = combined_score(pt)
        label = f"Beaufort key={key}"
        record(label, pt)
        marker = " <<<" if sc > 15 else ""
        print(f"  key={key:20s}: {pt[:55]}...  (score={sc:.1f}){marker}")

    # ── 5. Variant Beaufort decrypt ──────────────────────────────────────
    print("\n" + "=" * 70)
    print("5. VARIANT BEAUFORT DECRYPT (PT = CT + KEY mod 26)")
    print("=" * 70)
    for key in CANDIDATE_KEYS:
        pt = variant_beaufort_decrypt(YAR_CT, key)
        sc = combined_score(pt)
        label = f"VarBeau key={key}"
        record(label, pt)
        marker = " <<<" if sc > 15 else ""
        print(f"  key={key:20s}: {pt[:55]}...  (score={sc:.1f}){marker}")

    # ── 6. Atbash ────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("6. ATBASH (A<->Z, B<->Y, ...)")
    print("=" * 70)
    pt = atbash(YAR_CT)
    sc = combined_score(pt)
    label = "Atbash"
    record(label, pt)
    print(f"  {pt}")
    print(f"  score={sc:.1f}")

    # Also Atbash + Caesar
    for shift in range(1, 26):
        pt2 = caesar_shift_az(pt, shift)
        sc2 = combined_score(pt2)
        label2 = f"Atbash+Caesar shift={shift}"
        record(label2, pt2)
        if sc2 > 12:
            print(f"  +Caesar shift={shift:2d}: {pt2[:60]}...  (score={sc2:.1f}) <<<")

    # ── 7. Affine cipher ────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("7. AFFINE CIPHER (all valid a,b pairs where gcd(a,26)=1)")
    print("=" * 70)
    valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]
    print(f"  Valid 'a' values: {valid_a}")
    affine_count = 0
    best_affine = []
    for a in valid_a:
        for b in range(26):
            pt = affine_decrypt(YAR_CT, a, b)
            sc = combined_score(pt)
            label = f"Affine a={a},b={b}"
            record(label, pt)
            affine_count += 1
            best_affine.append((sc, a, b, pt))
    best_affine.sort(reverse=True)
    print(f"  Tested {affine_count} (a,b) pairs")
    print(f"  Top 5 affine results:")
    for sc, a, b, pt in best_affine[:5]:
        print(f"    a={a:2d}, b={b:2d}: {pt[:55]}...  (score={sc:.1f})")

    # ── 8. Reversed CT + Caesar ──────────────────────────────────────────
    print("\n" + "=" * 70)
    print("8. REVERSED CT + CAESAR SHIFTS")
    print("=" * 70)
    rev_ct = YAR_CT[::-1]
    print(f"  Reversed CT: {rev_ct[:60]}...")
    best_rev = []
    for shift in range(26):
        pt = caesar_shift_az(rev_ct, shift)
        sc = combined_score(pt)
        label = f"Reversed+Caesar-AZ shift={shift}"
        record(label, pt)
        best_rev.append((sc, shift, pt))
    best_rev.sort(reverse=True)
    print(f"  Top 5 reversed+Caesar results:")
    for sc, shift, pt in best_rev[:5]:
        print(f"    shift={shift:2d}: {pt[:55]}...  (score={sc:.1f})")

    # Also reversed + Vigenere with key candidates
    for key in CANDIDATE_KEYS:
        pt = vigenere_decrypt(rev_ct, key)
        sc = combined_score(pt)
        label = f"Reversed+Vigenere key={key}"
        record(label, pt)
        if sc > 12:
            print(f"    Reversed+Vig key={key}: {pt[:50]}... (score={sc:.1f}) <<<")

    # ── 9. Keyword-mixed alphabet (KRYPTOS) + Caesar ─────────────────────
    print("\n" + "=" * 70)
    print("9. KEYWORD-MIXED ALPHABET (KRYPTOS) + CAESAR SHIFTS")
    print("=" * 70)
    kw_alpha = make_keyword_alphabet("KRYPTOS")
    print(f"  Keyword alphabet: {kw_alpha}")
    best_kw = []
    for shift in range(26):
        pt = keyword_caesar_decrypt(YAR_CT, kw_alpha, shift)
        sc = combined_score(pt)
        label = f"KWAlpha-KRYPTOS+Caesar shift={shift}"
        record(label, pt)
        best_kw.append((sc, shift, pt))
    best_kw.sort(reverse=True)
    print(f"  Top 5 keyword+Caesar results:")
    for sc, shift, pt in best_kw[:5]:
        print(f"    shift={shift:2d}: {pt[:55]}...  (score={sc:.1f})")

    # Also try other keywords for mixed alphabets
    extra_keywords = ["PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "SANBORN", "SCHEIDT"]
    for kw in extra_keywords:
        kw_a = make_keyword_alphabet(kw)
        for shift in range(26):
            pt = keyword_caesar_decrypt(YAR_CT, kw_a, shift)
            sc = combined_score(pt)
            label = f"KWAlpha-{kw}+Caesar shift={shift}"
            record(label, pt)
            if sc > 15:
                print(f"  KW={kw} shift={shift}: {pt[:50]}... (score={sc:.1f}) <<<")

    # ── 10. Additional: Vigenere in KA-space ─────────────────────────────
    print("\n" + "=" * 70)
    print("10. VIGENERE IN KA-SPACE (using KA alphabet indices)")
    print("=" * 70)
    for key in CANDIDATE_KEYS:
        key_len = len(key)
        pt_chars = []
        for i in range(len(YAR_CT)):
            ct_idx = KA_IDX[YAR_CT[i]]
            key_idx = KA_IDX[key[i % key_len]]
            pt_chars.append(KA[(ct_idx - key_idx) % 26])
        pt = "".join(pt_chars)
        sc = combined_score(pt)
        label = f"Vigenere-KA key={key}"
        record(label, pt)
        marker = " <<<" if sc > 15 else ""
        print(f"  key={key:20s}: {pt[:55]}...  (score={sc:.1f}){marker}")

    # Also Beaufort in KA-space
    for key in CANDIDATE_KEYS:
        key_len = len(key)
        pt_chars = []
        for i in range(len(YAR_CT)):
            ct_idx = KA_IDX[YAR_CT[i]]
            key_idx = KA_IDX[key[i % key_len]]
            pt_chars.append(KA[(key_idx - ct_idx) % 26])
        pt = "".join(pt_chars)
        sc = combined_score(pt)
        label = f"Beaufort-KA key={key}"
        record(label, pt)
        if sc > 15:
            print(f"  Beau-KA key={key}: {pt[:50]}... (score={sc:.1f}) <<<")

    # ── FINAL RESULTS ────────────────────────────────────────────────────
    print("\n" + "=" * 80)
    print("FINAL RESULTS: TOP 20 MOST ENGLISH-LIKE OUTPUTS")
    print("=" * 80)

    all_results.sort(key=lambda x: x[0], reverse=True)

    for rank, (sc, label, pt) in enumerate(all_results[:20], 1):
        tc = trigram_count(pt)
        words = word_count(pt)
        qg = quadgram_score(pt) if QUADGRAMS else -99.0
        print(f"\n  #{rank:2d}  score={sc:.1f}  trigrams={tc}  words={len(words)}  qg={qg:.3f}/char")
        print(f"       method: {label}")
        print(f"       PT: {pt}")
        if words:
            # Show unique words found
            unique_words = sorted(set(w for w, _ in words), key=len, reverse=True)[:10]
            print(f"       words found: {', '.join(unique_words)}")

    # ── Summary stats ────────────────────────────────────────────────────
    total = len(all_results)
    above_15 = sum(1 for sc, _, _ in all_results if sc > 15)
    above_20 = sum(1 for sc, _, _ in all_results if sc > 20)
    print(f"\n{'=' * 80}")
    print(f"SUMMARY: {total} total outputs tested")
    print(f"  Above score 15: {above_15}")
    print(f"  Above score 20: {above_20}")
    best_sc, best_label, best_pt = all_results[0]
    print(f"  Best overall: score={best_sc:.1f}, method={best_label}")
    print(f"  Best PT: {best_pt}")

    # ── Quadgram analysis of top results ─────────────────────────────────
    if QUADGRAMS:
        print(f"\n{'=' * 80}")
        print("QUADGRAM ANALYSIS: Top 10 by quadgram score alone")
        print("=" * 80)
        qg_ranked = sorted(all_results, key=lambda x: quadgram_score(x[2]), reverse=True)
        for rank, (sc, label, pt) in enumerate(qg_ranked[:10], 1):
            qg = quadgram_score(pt)
            print(f"  #{rank:2d}  qg={qg:.3f}/char  combined={sc:.1f}")
            print(f"       method: {label}")
            print(f"       PT: {pt[:70]}...")

    print(f"\n{'=' * 80}")
    print("E-GRILLE-02 COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
