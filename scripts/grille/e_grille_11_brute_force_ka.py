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
E-GRILLE-11: Brute-force decrypt the Cardan grille extract using
the KA Vigenère tableau with thematic keywords.

The 106-char extract was read from the KA tableau through a physical mask.
Treat it as ciphertext and try every plausible keyword with Vigenère/Beaufort
decryption using the KA alphabet ordering as it appears on the sculpture.

Attack surface:
  - ~500 single thematic keywords (Kryptos, CIA, espionage, Egypt, Berlin, etc.)
  - 2-word and 3-word keyword combinations
  - Random keyword generation from thematic syllables
  - All three cipher variants (Vig, Beau, VarBeau)
  - Both KA and AZ alphabets
  - Keyword lengths 1-26+
  - Score: quadgrams + crib search + word detection
"""

from __future__ import annotations
import json
import random
import sys
import time
from collections import Counter
from itertools import product
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
CT_LEN = 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

CRIBS = [
    "EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLINCL",
    "EAST", "NORTH", "BERLIN", "CLOCK", "SHADOW", "LIGHT",
    "SLOWLY", "DESPERATELY", "INVISIBLE", "IQLUSION", "ILLUSION",
    "UNDERGROUND", "UNDERGRUUND", "BURIED", "LAYER", "PALIMPSEST",
    "ABSCISSA", "KRYPTOS", "BETWEEN", "SUBTLE", "SHADING",
    "ABSENCE", "TOTALLY", "POSSIBLE", "DIGGIN", "RUINS",
    "VIRTUALLY", "ANCIENT", "CARTER", "HOWARD", "EGYP",
    "PYRAMID", "DELIVER", "MESSAGE", "ENIGMA",
    "THEBERLIN", "WALLFEL", "HIEROGLYPH",
]

# ── Thematic keyword pools ──────────────────────────────────────────────────

KRYPTOS_WORDS = [
    # Sculpture
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "LIGHT", "EQUINOX",
    "ANTIPODES", "MEDUSA", "ENIGMA", "SANBORN", "SCHEIDT",
    # K1-K3 keywords
    "BETWEEN", "SUBTLE", "SHADING", "ABSENCE", "INVISIBLE",
    "IQLUSION", "ILLUSION", "SLOWLY", "DESPERATELY", "VIRTUALLY",
    "UNDERGROUND", "UNDERGRUUND",
    # K2 hints
    "IDBYROWS", "XLAYERTWO", "LAYERTWO",
    # CIA / Langley
    "LANGLEY", "AGENCY", "CENTRAL", "INTELLIGENCE", "VIRGINIA",
    "MCLEAN", "WEBSTER", "DIRECTOR",
    # Ed Scheidt
    "MATRIX", "VIGENERE", "BEAUFORT", "CIPHER", "CRYPTO",
    "MASKING", "TECHNIQUE", "PUZZLE",
    # Berlin / Cold War
    "BERLIN", "CLOCK", "WALL", "CHECKPOINT", "CHARLIE",
    "EAST", "WEST", "NORTH", "SOUTH", "NORTHEAST",
    "WELTZEITUHR", "ALEXANDERPLATZ",
    # Egypt / Carter
    "CARTER", "HOWARD", "TUTANKHAMUN", "EGYPT", "PHARAOH",
    "PYRAMID", "SPHINX", "CAIRO", "LUXOR", "THEBES",
    "TOMB", "SEAL", "HIEROGLYPH", "CANOPIC",
    # Espionage
    "COVERT", "SECRET", "HIDDEN", "CLASSIFIED", "REDACTED",
    "AGENT", "HANDLER", "DOUBLE", "DEFECTOR", "MOLE",
    "DEADROP", "SIGNAL", "FREQUENCY", "DURESS",
    # Navigation
    "COMPASS", "MAGNETIC", "LODESTONE", "BEARING", "AZIMUTH",
    "MERIDIAN", "LATITUDE", "LONGITUDE", "COORDINATES",
    # Misc Kryptos lore
    "PETRIFIED", "QUARTZ", "COPPER", "GRANITE", "MORSE",
    "WHIRLPOOL", "METEORITE", "GRILLE", "CARDAN",
    "DELIVER", "MESSAGE", "BURIED", "SOMEWHERE",
    # Le Carré
    "RUSSIA", "HOUSE", "SMILEY", "KARLA", "CIRCUS",
    "PERFECT", "SPY", "CORNWELL",
    # Colors / materials
    "VERDIGRIS", "PATINA", "OXIDIZE",
    # Short common keys
    "KEY", "CODE", "LOCK", "OPEN", "FIND", "SEEK",
    "REVEAL", "DECODE", "PLAIN", "CLEAR",
    # Numbers as words
    "NINETY", "SEVEN", "EIGHT", "ZERO", "ONE", "TWO",
    # Alphabet-related
    "ALPHABET", "TABLEAU", "KEYWORD",
    # Positions / directions
    "POSITION", "COLUMN", "ROW", "DIAGONAL",
    # Historical
    "NOVEMBER", "NINETEEN", "EIGHTY", "NINE", "FALL",
]

# Short keys to try exhaustively (1-4 letters from KA alphabet)
def generate_short_keys(max_len: int = 4) -> list[str]:
    """Generate all KA-alphabet keys up to max_len."""
    keys = []
    for length in range(1, max_len + 1):
        if length <= 2:
            for combo in product(KA, repeat=length):
                keys.append("".join(combo))
        # 3-4 letter: too many, skip (26^3 = 17K, 26^4 = 456K)
    return keys


# ── Scoring ──────────────────────────────────────────────────────────────────

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

def has_cribs(text: str) -> list[tuple[str, int]]:
    found = []
    upper = text.upper()
    for crib in CRIBS:
        idx = upper.find(crib)
        if idx >= 0:
            found.append((crib, idx))
    return found

# Load a small English word set for word detection
_WORDS: set[str] | None = None

def _load_words() -> set[str]:
    global _WORDS
    if _WORDS is not None:
        return _WORDS
    for p in [Path("wordlists/english.txt"), Path("../wordlists/english.txt")]:
        if p.exists():
            all_words = [w.strip().upper() for w in p.read_text().splitlines()]
            _WORDS = {w for w in all_words if 4 <= len(w) <= 15 and w.isalpha()}
            return _WORDS
    _WORDS = set()
    return _WORDS

def count_english_words(text: str, min_len: int = 4) -> list[str]:
    """Find English words in plaintext (greedy, overlapping)."""
    words = _load_words()
    if not words:
        return []
    upper = text.upper()
    found = []
    for length in range(min(15, len(upper)), min_len - 1, -1):
        for i in range(len(upper) - length + 1):
            substr = upper[i:i+length]
            if substr in words:
                found.append(substr)
    return found


# ── Cipher functions ─────────────────────────────────────────────────────────

def vig_decrypt(ct: str, key: str, alpha: str) -> str:
    return "".join(alpha[(alpha.index(c) - alpha.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))

def beau_decrypt(ct: str, key: str, alpha: str) -> str:
    return "".join(alpha[(alpha.index(key[i % len(key)]) - alpha.index(c)) % 26]
                   for i, c in enumerate(ct))

def varbeau_decrypt(ct: str, key: str, alpha: str) -> str:
    # Same as vig for standard alphabet, different for KA
    return vig_decrypt(ct, key, alpha)


# ── Attack 1: All thematic keywords ─────────────────────────────────────────

def attack_single_keywords() -> list[dict]:
    """Try every single thematic keyword."""
    print("=" * 70)
    print("ATTACK 1: Single thematic keywords")
    print(f"  Keywords: {len(KRYPTOS_WORDS)} | Ciphers: 2 | Alphabets: 2")
    print(f"  Total configs: {len(KRYPTOS_WORDS) * 2 * 2}")
    print("=" * 70)
    print()

    results = []
    best_score = -99999
    best_result = None
    configs_tested = 0

    for key in KRYPTOS_WORDS:
        key = key.upper()
        # Validate key letters exist in alphabet
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            if not all(c in alpha for c in key):
                continue
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(GRILLE_CT, key, alpha)
                except (ValueError, IndexError):
                    continue

                configs_tested += 1
                sc = score_text(pt)
                crib_hits = has_cribs(pt)

                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "keyword": key, "alphabet": alpha_name,
                        "cipher": cipher_name, "score": sc,
                        "plaintext": pt, "crib_hits": crib_hits,
                    }

                if crib_hits or sc > -750:
                    results.append({
                        "keyword": key, "alphabet": alpha_name,
                        "cipher": cipher_name, "score": sc,
                        "plaintext": pt, "crib_hits": crib_hits,
                    })

    results.sort(key=lambda r: -r["score"])

    print(f"  Configs tested: {configs_tested}")
    print(f"  Results above -750: {len(results)}")
    if best_result:
        print(f"  Best: {best_result['cipher']}/{best_result['alphabet']} "
              f"key={best_result['keyword']} score={best_result['score']:.1f}")
        print(f"    PT: {best_result['plaintext'][:60]}...")
        if best_result['crib_hits']:
            print(f"    *** CRIB HITS: {best_result['crib_hits']} ***")

    print(f"\n  Top 15:")
    for r in results[:15]:
        cribs = f" CRIBS={r['crib_hits']}" if r['crib_hits'] else ""
        words = count_english_words(r['plaintext'])
        word_str = f" words=[{','.join(words[:5])}]" if words else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword']:<16}{cribs}{word_str}")
        print(f"             {r['plaintext'][:70]}")
    print()
    return results


# ── Attack 2: Short exhaustive keys (1-2 letter) ───────────────────────────

def attack_short_keys() -> list[dict]:
    """Exhaustive search of 1-2 letter keys in KA alphabet."""
    short_keys = generate_short_keys(2)
    print("=" * 70)
    print(f"ATTACK 2: Short exhaustive keys (1-2 letters in KA)")
    print(f"  Keys: {len(short_keys)} | Ciphers: 2 | Alphabets: 2")
    print(f"  Total configs: {len(short_keys) * 2 * 2}")
    print("=" * 70)
    print()

    results = []
    best_score = -99999
    best_result = None

    for key in short_keys:
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            if not all(c in alpha for c in key):
                continue
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(GRILLE_CT, key, alpha)
                except (ValueError, IndexError):
                    continue

                sc = score_text(pt)
                if sc > best_score:
                    best_score = sc
                    best_result = {
                        "keyword": key, "alphabet": alpha_name,
                        "cipher": cipher_name, "score": sc,
                        "plaintext": pt,
                    }

                crib_hits = has_cribs(pt)
                if crib_hits or sc > -750:
                    results.append({
                        "keyword": key, "alphabet": alpha_name,
                        "cipher": cipher_name, "score": sc,
                        "plaintext": pt, "crib_hits": crib_hits,
                    })

    results.sort(key=lambda r: -r["score"])

    print(f"  Best: {best_result['cipher']}/{best_result['alphabet']} "
          f"key={best_result['keyword']} score={best_result['score']:.1f}")
    print(f"    PT: {best_result['plaintext'][:60]}...")
    print(f"\n  Top 10:")
    for r in results[:10]:
        cribs = f" CRIBS={r['crib_hits']}" if r.get('crib_hits') else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword']:<6}{cribs}")
        print(f"             {r['plaintext'][:70]}")
    print()
    return results


# ── Attack 3: Two-keyword combinations ──────────────────────────────────────

def attack_keyword_combos() -> list[dict]:
    """Try concatenated pairs of short thematic keywords."""
    print("=" * 70)
    print("ATTACK 3: Two-keyword combinations")
    print("=" * 70)
    print()

    # Use shorter keywords for combinations (otherwise space explodes)
    short_words = [w.upper() for w in KRYPTOS_WORDS if len(w) <= 8]
    # Also add some very short words
    short_words.extend(["KEY", "SPY", "CIA", "NSA", "K", "IV", "V",
                        "VI", "VII", "AB", "CD", "EF"])
    short_words = list(set(short_words))

    print(f"  Base words: {len(short_words)}")
    print(f"  Pairs: ~{len(short_words)**2} (testing up to 50K)")

    results = []
    best_score = -99999
    best_result = None
    tested = 0

    for w1 in short_words:
        for w2 in short_words:
            key = w1 + w2
            if len(key) > 26 or len(key) < 3:
                continue

            for alpha_name, alpha in [("KA", KA)]:  # Focus on KA
                if not all(c in alpha for c in key):
                    continue
                for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    try:
                        pt = cipher_fn(GRILLE_CT, key, alpha)
                    except (ValueError, IndexError):
                        continue

                    tested += 1
                    sc = score_text(pt)
                    if sc > best_score:
                        best_score = sc
                        best_result = {
                            "keyword": key, "components": [w1, w2],
                            "alphabet": alpha_name, "cipher": cipher_name,
                            "score": sc, "plaintext": pt,
                        }

                    crib_hits = has_cribs(pt)
                    if crib_hits or sc > -750:
                        results.append({
                            "keyword": key, "components": [w1, w2],
                            "alphabet": alpha_name, "cipher": cipher_name,
                            "score": sc, "plaintext": pt,
                            "crib_hits": crib_hits,
                        })

            if tested > 50000:
                break
        if tested > 50000:
            break

    results.sort(key=lambda r: -r["score"])

    print(f"  Configs tested: {tested}")
    if best_result:
        print(f"  Best: {best_result['cipher']}/{best_result['alphabet']} "
              f"key={best_result['keyword']} ({best_result['components']}) "
              f"score={best_result['score']:.1f}")
        print(f"    PT: {best_result['plaintext'][:60]}...")
    print(f"\n  Top 10:")
    for r in results[:10]:
        cribs = f" CRIBS={r['crib_hits']}" if r.get('crib_hits') else ""
        words = count_english_words(r['plaintext'])
        word_str = f" words=[{','.join(words[:5])}]" if words else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword']:<20}{cribs}{word_str}")
    print()
    return results


# ── Attack 4: Random keyword generation ─────────────────────────────────────

def attack_random_keywords(n_trials: int = 100000) -> list[dict]:
    """Generate random thematic keywords and test them."""
    print("=" * 70)
    print(f"ATTACK 4: Random keyword generation ({n_trials:,} trials)")
    print("=" * 70)
    print()

    # Syllable pools from Kryptos themes
    prefixes = [
        "KRYP", "PAL", "ABS", "SHAD", "SAN", "SCHE",
        "BER", "CLO", "EAS", "NOR", "LIG", "ANT",
        "MED", "ENI", "VIG", "BEA", "CIP", "MAT",
        "LAN", "AGE", "CEN", "INT", "VIR", "MCL",
        "WEB", "DIR", "CAR", "HOW", "TUT", "EGY",
        "PHA", "PYR", "SPH", "CAI", "LUX", "THE",
        "COV", "SEC", "HID", "CLA", "RED", "DOU",
        "DEF", "MOL", "SIG", "FRE", "COM", "MAG",
        "LOD", "PET", "QUA", "COP", "GRA", "MOR",
        "GRI", "DEL", "MES", "BUR", "RUS", "HOU",
        "SMI", "KAR", "CIR", "PER", "COR", "VER",
    ]

    suffixes = [
        "TOS", "IMPSEST", "CISSA", "OW", "BORN", "IDT",
        "LIN", "CK", "ST", "TH", "HT", "IPODES",
        "USA", "GMA", "ENERE", "UFORT", "HER", "RIX",
        "GLEY", "NCY", "TRAL", "ENCE", "INIA", "EAN",
        "STER", "ECTOR", "TER", "ARD", "ANKHAMUN", "PT",
        "RAOH", "AMID", "INX", "RO", "OR", "BES",
        "ERT", "RET", "DEN", "SSIFIED", "ACTED", "BLE",
        "ECTOR", "E", "NAL", "QUENCY", "PASS", "NETIC",
        "STONE", "RIFIED", "RTZ", "PER", "NITE", "SE",
        "LLE", "IVER", "SAGE", "IED", "SIA", "SE",
        "LEY", "LA", "CUS", "FECT", "NWELL", "DIGRIS",
    ]

    random.seed(42)
    results = []
    best_score = -99999
    best_result = None

    for trial in range(n_trials):
        # Generate keyword: random combination of 1-3 parts
        n_parts = random.randint(1, 3)
        parts = []
        for _ in range(n_parts):
            strategy = random.random()
            if strategy < 0.3:
                # Pure thematic word
                parts.append(random.choice(KRYPTOS_WORDS).upper())
            elif strategy < 0.6:
                # Prefix + suffix
                parts.append(random.choice(prefixes) + random.choice(suffixes))
            elif strategy < 0.8:
                # Random KA letters
                length = random.randint(3, 12)
                parts.append("".join(random.choice(KA) for _ in range(length)))
            else:
                # Prefix only or suffix only
                parts.append(random.choice(prefixes + suffixes))

        key = "".join(parts).upper()
        if len(key) < 2 or len(key) > 30:
            continue

        alpha_name, alpha = ("KA", KA) if random.random() < 0.7 else ("AZ", AZ)
        if not all(c in alpha for c in key):
            continue

        cipher_fn = random.choice([vig_decrypt, beau_decrypt])
        cipher_name = "vig" if cipher_fn == vig_decrypt else "beau"

        try:
            pt = cipher_fn(GRILLE_CT, key, alpha)
        except (ValueError, IndexError):
            continue

        sc = score_text(pt)
        if sc > best_score:
            best_score = sc
            best_result = {
                "keyword": key, "alphabet": alpha_name,
                "cipher": cipher_name, "score": sc,
                "plaintext": pt,
            }

        crib_hits = has_cribs(pt)
        if crib_hits or sc > -750:
            results.append({
                "keyword": key, "alphabet": alpha_name,
                "cipher": cipher_name, "score": sc,
                "plaintext": pt, "crib_hits": crib_hits,
            })

        if (trial + 1) % 25000 == 0:
            print(f"  ...{trial + 1:,} trials, best score: {best_score:.1f}")

    results.sort(key=lambda r: -r["score"])

    print(f"\n  Trials: {n_trials:,}")
    if best_result:
        print(f"  Best: {best_result['cipher']}/{best_result['alphabet']} "
              f"key={best_result['keyword']} score={best_result['score']:.1f}")
        print(f"    PT: {best_result['plaintext'][:60]}...")
    print(f"\n  Top 15:")
    for r in results[:15]:
        cribs = f" CRIBS={r['crib_hits']}" if r.get('crib_hits') else ""
        words = count_english_words(r['plaintext'])
        word_str = f" words=[{','.join(words[:3])}]" if words else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword'][:25]:<25}{cribs}{word_str}")
    print()
    return results


# ── Attack 5: KA tableau row labels as key ──────────────────────────────────

def attack_tableau_structural():
    """Use the tableau's own structure as the key."""
    print("=" * 70)
    print("ATTACK 5: Tableau structural keys")
    print("=" * 70)
    print()

    # The KA tableau has 28 rows, each labeled by a letter of KA
    # Row labels: K, R, Y, P, T, O, S, A, B, C, D, E, F, G, H, I, J, L, M, N, Q, U, V, W, X, Z, K, R
    # (wraps after 26)
    row_labels = KA + KA[:2]  # 28 rows
    print(f"  KA row labels (28 rows): {row_labels}")

    # The grille has 107 holes across 28 rows.
    # Each hole's row determines a "key letter" from the row label.
    # Parse the mask to get the row for each hole.

    MASK_ROWS = [
        "000000001010100000000010000000001~~",
        "100000000010000001000100110000011~~",
        "000000000000001000000000000000011~~",
        "00000000000000000000100000010011~~",
        "00000001000000001000010000000011~~",
        "000000001000000000000000000000011~",
        "100000000000000000000000000000011",
        "00000000000000000000000100000100~~",
        "0000000000000000000100000001000~~",
        "0000000000000000000000000000100~~",
        "000000001000000000000000000000~~",
        "00000110000000000000000000000100~~",
        "00000000000000100010000000000001~~",
        "00000000000100000000000000001000~~",
        "000110100001000000000000001000010~~",
        "00001010000000000000000001000001~~",
        "001001000010010000000000000100010~~",
        "00000000000100000000010000010001~~",
        "000000000000010001001000000010001~~",
        "00000000000000001001000000000100~~",
        "000000001100000010100100010001001~~",
        "000000000000000100001010100100011~",
        "00000000100000000000100001100001~~~",
        "100000000000000000001000001000010~",
        "10000001000001000000100000000001~~",
        "000010000000000000010000100000011",
        "0000000000000000000100001000000011",
        "00000000000000100000001010000001~~",
    ]

    # Extract hole positions (row, col) for each '0' that's NOT '~'
    holes = []
    for row_idx, mask in enumerate(MASK_ROWS):
        for col_idx, c in enumerate(mask):
            if c == '0':
                holes.append((row_idx, col_idx))

    print(f"  Total holes: {len(holes)}")

    # The key implied by row labels for each hole position
    row_key = "".join(row_labels[h[0]] for h in holes)
    print(f"  Row-label key ({len(row_key)} chars): {row_key[:60]}...")

    # Use this as the key to decrypt the grille extract
    # But extract is 106 chars and we have 107 holes... take first 106
    if len(row_key) >= CT_LEN:
        key_106 = row_key[:CT_LEN]

        for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
                if not all(c in alpha for c in key_106):
                    continue
                try:
                    pt = cipher_fn(GRILLE_CT, key_106, alpha)
                except (ValueError, IndexError):
                    continue

                sc = score_text(pt)
                crib_hits = has_cribs(pt)
                words = count_english_words(pt)
                print(f"  {cipher_name}/{alpha_name} row-label key: score={sc:.1f}")
                print(f"    PT: {pt[:70]}...")
                if crib_hits:
                    print(f"    *** CRIB HITS: {crib_hits} ***")
                if words:
                    print(f"    Words: {words[:10]}")

    # Also try: column indices of holes as a numeric key
    col_key_letters = "".join(KA[h[1] % 26] for h in holes)[:CT_LEN]
    print(f"\n  Column-index key: {col_key_letters[:60]}...")

    for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
        for alpha_name, alpha in [("KA", KA)]:
            try:
                pt = cipher_fn(GRILLE_CT, col_key_letters, alpha)
            except (ValueError, IndexError):
                continue
            sc = score_text(pt)
            crib_hits = has_cribs(pt)
            words = count_english_words(pt)
            print(f"  {cipher_name}/{alpha_name} col-index key: score={sc:.1f}")
            print(f"    PT: {pt[:70]}...")
            if crib_hits:
                print(f"    *** CRIB HITS: {crib_hits} ***")
            if words:
                print(f"    Words: {words[:10]}")

    print()


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    print()
    print("#" * 70)
    print("#  E-GRILLE-11: Brute-force KA-tableau decrypt of grille extract")
    print("#" * 70)
    print()
    print(f"  CT: {GRILLE_CT}")
    print(f"  Length: {CT_LEN}")
    print(f"  KA: {KA}")
    print()

    _load_quadgrams()
    _load_words()

    t0 = time.time()

    r1 = attack_single_keywords()
    r2 = attack_short_keys()
    r3 = attack_keyword_combos()
    r4 = attack_random_keywords(100_000)
    attack_tableau_structural()

    elapsed = time.time() - t0

    # ── Grand summary ──────────────────────────────────────────────────
    all_results = r1 + r2 + r3 + r4
    all_results.sort(key=lambda r: -r["score"])

    print()
    print("=" * 70)
    print(f"GRAND SUMMARY ({elapsed:.1f}s)")
    print("=" * 70)

    any_cribs = [r for r in all_results if r.get("crib_hits")]
    if any_cribs:
        print(f"\n  *** {len(any_cribs)} RESULTS WITH CRIB HITS ***")
        for r in any_cribs[:10]:
            print(f"    {r['cipher']}/{r['alphabet']} key={r['keyword']}: {r['crib_hits']}")
            print(f"      {r['plaintext'][:60]}")

    print(f"\n  Top 20 overall by quadgram score:")
    for r in all_results[:20]:
        cribs = f" CRIBS={r.get('crib_hits')}" if r.get('crib_hits') else ""
        words = count_english_words(r['plaintext'])
        word_str = f" [{','.join(words[:3])}]" if words else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword'][:30]:<30}{cribs}{word_str}")

    # Save results
    outfile = Path("results/e_grille_11_results.json")
    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json.dumps({
        "experiment": "E-GRILLE-11",
        "elapsed_seconds": round(elapsed, 1),
        "total_configs": len(all_results),
        "any_crib_found": bool(any_cribs),
        "top_20": [{k: v for k, v in r.items() if k != "plaintext"}
                   for r in all_results[:20]],
    }, indent=2))
    print(f"\n  Results saved to {outfile}")
    print()


if __name__ == "__main__":
    main()
