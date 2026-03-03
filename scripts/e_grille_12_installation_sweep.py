#!/usr/bin/env python3
"""
E-GRILLE-12: Exhaustive installation-derived keyword sweep on the
Cardan grille extract (106 chars) as ciphertext.

Every keyword derivable from the Kryptos installation:
  - K1-K3 keywords and plaintext words
  - Physical materials and features
  - Geodetic markers (LOOMIS, BOWEN, coordinates)
  - Anomaly words (misspellings, YAR, OFLNUXZ, ILM)
  - CIA/Scheidt vocabulary
  - Progressive compound keys (K1 key + K2 key, etc.)
  - Coordinate-derived keys (degrees, minutes, seconds as letters)
  - Every 4-12 letter word from the English wordlist (370K)
"""

from __future__ import annotations
import json
import sys
import time
from pathlib import Path
from multiprocessing import Pool, cpu_count

# ── Constants ────────────────────────────────────────────────────────────────

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
CT_LEN = 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

CRIBS = [
    "EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLIN",
    "EAST", "NORTH", "CLOCK", "SHADOW", "LIGHT", "SLOWLY",
    "DESPERATELY", "INVISIBLE", "UNDERGROUND", "BURIED",
    "LAYER", "PALIMPSEST", "ABSCISSA", "KRYPTOS", "BETWEEN",
    "SUBTLE", "ABSENCE", "CARTER", "HOWARD", "PYRAMID",
    "DELIVER", "MESSAGE", "ENIGMA", "PASSAGE", "BONES",
    "EARTH", "TWELVE", "MONKEYS", "SECRET", "GALLERY",
    "PHOTOGRAPHS", "CLASSIFIED",
]

# ── Installation-derived keywords ───────────────────────────────────────────

# K1-K3 keywords
K_KEYWORDS = [
    "PALIMPSEST", "ABSCISSA", "KRYPTOS",
]

# K1 plaintext words (significant only)
K1_PT_WORDS = [
    "BETWEEN", "SUBTLE", "SHADING", "ABSENCE", "LIGHT",
    "NAMELESS", "LINEATION", "PAINTING", "FLOWERS", "FADING",
    "BLOOM", "DENIES", "ABEYANCE", "IDENTITY", "ACROSS",
    "REFLECTION", "FOLLOWING", "FLOSSINESS", "ENDURED",
    "PERPETUITY", "FOREVER", "ILLUSTRATING", "VISIBLE",
    "CIPHERS", "ILLUSION",
]

# K2 plaintext words
K2_PT_WORDS = [
    "TOTALLY", "INVISIBLE", "PROGRESS", "POSSIBLE", "WONDER",
    "GOTTEN", "PICTURES", "CLASSIFIED", "PHOTOGRAPHY",
    "ABSOLUTELY", "SECRET", "SENSITIVE", "MILITARY",
    "INSTALLATIONS", "SOVIET", "UNION", "OBSESSED",
    "RESTORING", "GERMAN", "ACROSS", "REFLECTION",
    "GALLERY", "CLOSED", "INCREDIBLY", "PHOTOGRAPHS",
    "TRANSMITTED", "UNDERGROUND", "UNKNOWN", "LOCATION",
    "IDBYROWS",
]

# K3 plaintext words
K3_PT_WORDS = [
    "SLOWLY", "DESPERATELY", "REMAINS", "PASSAGE", "DEBRIS",
    "ENCRYPTED", "INVISIBLE", "AIRWELLS", "MASTODONIC",
    "SLIME", "TRUST", "PLACING", "BONES", "BELOW",
    "EARTH", "UNDER", "MUNDANITY", "STONES", "TWELVE",
    "MONKEYS", "ANYTHING",
]

# Physical installation
PHYSICAL = [
    "GRANITE", "COPPER", "LODESTONE", "PETRIFIED", "QUARTZ",
    "SLATE", "METEORITE", "WHIRLPOOL", "COMPASS", "SCREEN",
    "WALKWAY", "COURTYARD", "CAFETERIA", "VERDIGRIS", "PATINA",
    "OXIDIZE", "SCULPTURE", "BARRIER", "ENTRANCE", "GRASSES",
    "MISCANTHUS", "OUTCROPS", "STRATA", "PLATE",
]

# Anomalies (misspellings as on sculpture)
ANOMALIES = [
    "PALIMPCEST", "IQLUSION", "UNDERGRUUND", "DESPARATLY",
    "DIGETAL", "YAR", "OFLNUXZ", "ILM", "WHA", "HILL",
    "EQUINOX", "LUX",
]

# Geodetic markers
GEODETIC = [
    "LOOMIS", "BOWEN", "MCLEAN", "LANGLEY", "VIRGINIA",
    "USGS",
]

# CIA / Scheidt
CIA_SCHEIDT = [
    "SANBORN", "SCHEIDT", "WEBSTER", "CARTER", "HOWARD",
    "DIRECTOR", "AGENCY", "CENTRAL", "INTELLIGENCE",
    "MATRIX", "VIGENERE", "BEAUFORT", "CIPHER", "CRYPTO",
    "MASKING", "TECHNIQUE", "KEYSPLIT", "COMBINER",
    "TRANSPOSITION", "SUBSTITUTION", "SHIFTING",
    "SYSTEMS", "LAYERS", "CODES",
]

# K2 ending variants
K2_ENDINGS = [
    "IDBYROWS", "XLAYERTWO", "LAYERTWO",
]

# Thematic / espionage
THEMATIC = [
    "BERLIN", "CLOCK", "EAST", "NORTH", "SOUTH", "WEST",
    "NORTHEAST", "CHECKPOINT", "CHARLIE", "WELTZEITUHR",
    "ALEXANDERPLATZ", "EGYPT", "PHARAOH", "PYRAMID",
    "SPHINX", "CAIRO", "LUXOR", "THEBES", "TOMB",
    "HIEROGLYPH", "CANOPIC", "TUTANKHAMUN",
    "COVERT", "SECRET", "HIDDEN", "CLASSIFIED",
    "AGENT", "HANDLER", "DOUBLE", "DEFECTOR", "MOLE",
    "DEADROP", "SIGNAL", "DURESS", "COMPASS",
    "MAGNETIC", "BEARING", "AZIMUTH", "MERIDIAN",
    "LATITUDE", "LONGITUDE", "COORDINATES",
    "DELIVER", "MESSAGE", "BURIED", "SOMEWHERE",
    "RUSSIA", "HOUSE", "SMILEY", "KARLA", "CIRCUS",
    "CORNWELL", "LECARRE",
    "FOLD", "OVERLAY", "TABLEAU", "GRILLE", "CARDAN",
    "MASK", "POSITION", "READING", "ORDER",
    "LAYER", "TRANSMISSION", "DRYAD",
]

# Coordinate-derived keys
# LOOMIS: 38°57'06.22"N, 077°08'48.14"W
# K2 decoded coords: ~38°57'6.5"N, 77°8'44"W
# Convert numbers to letters: A=1, B=2, ... or use the digits
COORD_KEYS = [
    # LOOMIS coords as letter sequences
    "CHIG", "CHIGFB", "CHIGFBBB",  # 38=CH, 57=EG, 06=F, 22=V → CHEGGFV?
    # Actually: digits → letters by A=1...
    # 38 57 06 22 N → C,H,E,G,K,F,B,B,N
    "CHEGKFBBN",  # LOOMIS lat digits→letters
    # 077 08 48 14 W → G,G,H,D,H,A,D,W
    "GGHDHADW",  # LOOMIS lon digits→letters
    # Combined
    "CHEGKFBBNGGHDHADW",
    # Just the significant digits
    "CHEG", "GGHD",
    # K2 decoded coordinates raw
    "THIRTYEIGHT", "FIFTYSEVEN", "SEVENTYSEVEN",
    # Degrees as words
    "DEGREESNORTH", "DEGREESWEST",
]

# Progressive/compound keys (concatenated keywords from different sections)
def generate_compound_keys() -> list[str]:
    """Generate compound keys from K1-K3 keywords and installation words."""
    bases = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT"]
    modifiers = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "LIGHT",
        "EQUINOX", "BERLIN", "CLOCK", "EAST", "NORTH",
        "LAYER", "MASK", "GRILLE", "FOLD", "YAR",
        "IDBYROWS", "XLAYERTWO", "LODESTONE", "LOOMIS", "BOWEN",
        "COMPASS", "QUARTZ", "COPPER", "LUX", "ILM",
        "OFLNUXZ", "HILL", "CARTER", "EGYPT", "TOMB",
        "BURIED", "SECRET", "HIDDEN", "INVISIBLE",
        "POSITION", "TABLEAU", "CARDAN", "KEY",
    ]

    compounds = []
    for b in bases:
        for m in modifiers:
            if b != m:
                # Forward
                c = b + m
                if 5 <= len(c) <= 26:
                    compounds.append(c)
                # Reverse
                c = m + b
                if 5 <= len(c) <= 26:
                    compounds.append(c)

    # Also: K1key+K2key+K3key triple
    compounds.append("PALIMPSESTABSCISSAKRYPTOS")
    compounds.append("KRYPTOSABSCISSAPALIMPSEST")
    compounds.append("ABSCISSAKRYPTOSPALIMPSEST")

    # Anomaly-derived
    compounds.append("QAECL")   # First letters of misspelled words' wrong chars
    compounds.append("QACEI")   # Anomaly pool subset
    compounds.append("EQUINOXLUX")
    compounds.append("LUXEQUINOX")
    compounds.append("YAREQUINOX")
    compounds.append("EQUINOXYARD")
    compounds.append("ILMYAR")
    compounds.append("YARILM")
    compounds.append("OFLNUXZYAR")
    compounds.append("YAROFLNUXZ")

    return list(set(compounds))


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


# ── Cipher functions ─────────────────────────────────────────────────────────

def vig_decrypt(ct: str, key: str, alpha: str) -> str:
    return "".join(alpha[(alpha.index(c) - alpha.index(key[i % len(key)])) % 26]
                   for i, c in enumerate(ct))

def beau_decrypt(ct: str, key: str, alpha: str) -> str:
    return "".join(alpha[(alpha.index(key[i % len(key)]) - alpha.index(c)) % 26]
                   for i, c in enumerate(ct))


# ── Worker for parallel dictionary sweep ────────────────────────────────────

def _dict_worker(args: tuple) -> list[dict]:
    """Test a batch of keywords."""
    keywords, threshold = args
    _load_quadgrams()
    results = []

    for key in keywords:
        key = key.upper()
        if not key.isalpha() or len(key) < 4:
            continue

        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            if not all(c in alpha for c in key):
                continue
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(GRILLE_CT, key, alpha)
                except (ValueError, IndexError):
                    continue

                sc = score_text(pt)
                crib_hits = has_cribs(pt)

                if crib_hits or sc > threshold:
                    results.append({
                        "keyword": key,
                        "alphabet": alpha_name,
                        "cipher": cipher_name,
                        "score": sc,
                        "plaintext": pt,
                        "crib_hits": crib_hits,
                        "key_len": len(key),
                    })

    return results


# ── Main sweep ──────────────────────────────────────────────────────────────

def main():
    print()
    print("#" * 70)
    print("#  E-GRILLE-12: Installation-derived keyword sweep")
    print("#  CT: Cardan grille extract (106 chars)")
    print("#  Alphabets: KA + AZ | Ciphers: Vig + Beau")
    print("#" * 70)
    print()

    _load_quadgrams()
    t0 = time.time()

    # ── Phase 1: Curated installation keywords ──────────────────────────
    print("=" * 70)
    print("PHASE 1: Curated installation keywords")
    print("=" * 70)

    curated = list(set(
        K_KEYWORDS + K1_PT_WORDS + K2_PT_WORDS + K3_PT_WORDS +
        PHYSICAL + ANOMALIES + GEODETIC + CIA_SCHEIDT + K2_ENDINGS +
        THEMATIC + COORD_KEYS + generate_compound_keys()
    ))
    print(f"  Total curated keywords: {len(curated)}")

    curated_results = _dict_worker((curated, -800))
    curated_results.sort(key=lambda r: -r["score"])

    crib_hits = [r for r in curated_results if r.get("crib_hits")]
    print(f"  Results above -800: {len(curated_results)}")
    print(f"  Results with crib hits: {len(crib_hits)}")

    if crib_hits:
        print(f"\n  *** CRIB HITS ***")
        for r in crib_hits[:20]:
            print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
                  f"key={r['keyword'][:30]} cribs={r['crib_hits']}")
            print(f"             {r['plaintext'][:70]}")

    print(f"\n  Top 20 by score:")
    for r in curated_results[:20]:
        cribs = f" cribs={r['crib_hits']}" if r.get('crib_hits') else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword'][:30]:<30} len={r['key_len']}{cribs}")
        print(f"             {r['plaintext'][:70]}")
    print()

    # ── Phase 2: Full English dictionary (4-12 letters) ─────────────────
    print("=" * 70)
    print("PHASE 2: Full English dictionary sweep (4-12 letter words)")
    print("=" * 70)

    wordlist = []
    for p in [Path("wordlists/english.txt"), Path("../wordlists/english.txt")]:
        if p.exists():
            wordlist = [w.strip().upper() for w in p.read_text().splitlines()
                        if w.strip().isalpha() and 4 <= len(w.strip()) <= 12]
            break

    print(f"  Dictionary words (4-12 chars): {len(wordlist)}")

    # Parallel sweep
    workers = min(cpu_count(), 28)
    chunk_size = max(1, len(wordlist) // (workers * 4))
    chunks = [(wordlist[i:i+chunk_size], -700)
              for i in range(0, len(wordlist), chunk_size)]

    print(f"  Workers: {workers}, chunks: {len(chunks)}")
    print(f"  Threshold: -700 (show only strong candidates)")

    dict_results = []
    with Pool(workers) as pool:
        for batch in pool.imap_unordered(_dict_worker, chunks):
            dict_results.extend(batch)

    dict_results.sort(key=lambda r: -r["score"])

    crib_hits_dict = [r for r in dict_results if r.get("crib_hits")]
    print(f"\n  Results above -700: {len(dict_results)}")
    print(f"  Results with crib hits: {len(crib_hits_dict)}")

    if crib_hits_dict:
        print(f"\n  *** DICTIONARY CRIB HITS ***")
        for r in crib_hits_dict[:30]:
            print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
                  f"key={r['keyword'][:20]} cribs={r['crib_hits']}")
            print(f"             {r['plaintext'][:70]}")

    print(f"\n  Top 30 by score:")
    for r in dict_results[:30]:
        cribs = f" cribs={r['crib_hits']}" if r.get('crib_hits') else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword'][:20]:<20} len={r['key_len']}{cribs}")
    print()

    # ── Phase 3: Dictionary 2-word compounds (top words only) ───────────
    print("=" * 70)
    print("PHASE 3: Two-word dictionary compounds")
    print("=" * 70)

    # Use top-scoring single words as bases for compounds
    top_singles = set()
    for r in dict_results[:200]:
        top_singles.add(r["keyword"])
    for r in curated_results[:100]:
        top_singles.add(r["keyword"])

    # Add installation must-haves
    must_have = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "LIGHT",
        "EQUINOX", "LOOMIS", "BOWEN", "LODESTONE", "COMPASS",
        "QUARTZ", "GRILLE", "CARDAN", "SCHEIDT", "SANBORN",
        "BERLIN", "CLOCK", "LAYER", "MASK", "FOLD",
        "COPPER", "WHIRLPOOL", "PETRIFIED", "YAR",
    ]
    top_singles.update(must_have)
    top_singles = list(top_singles)

    print(f"  Base words: {len(top_singles)}")
    print(f"  Pairs to test: ~{len(top_singles)**2}")

    compound_results = []
    for w1 in top_singles:
        batch_keys = []
        for w2 in must_have:  # Compound each top word with must-haves
            if w1 != w2:
                key = w1 + w2
                if 6 <= len(key) <= 26:
                    batch_keys.append(key)
                key = w2 + w1
                if 6 <= len(key) <= 26:
                    batch_keys.append(key)
        results = _dict_worker((batch_keys, -750))
        compound_results.extend(results)

    compound_results.sort(key=lambda r: -r["score"])

    crib_hits_comp = [r for r in compound_results if r.get("crib_hits")]
    print(f"\n  Compound results above -750: {len(compound_results)}")
    print(f"  With crib hits: {len(crib_hits_comp)}")

    if crib_hits_comp:
        print(f"\n  *** COMPOUND CRIB HITS ***")
        for r in crib_hits_comp[:20]:
            print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
                  f"key={r['keyword'][:30]} cribs={r['crib_hits']}")

    print(f"\n  Top 20 compounds:")
    for r in compound_results[:20]:
        cribs = f" cribs={r['crib_hits']}" if r.get('crib_hits') else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword'][:35]:<35} len={r['key_len']}{cribs}")
    print()

    # ── Grand Summary ──────────────────────────────────────────────────
    elapsed = time.time() - t0
    all_results = curated_results + dict_results + compound_results
    all_results.sort(key=lambda r: -r["score"])

    all_crib_hits = [r for r in all_results if r.get("crib_hits")]
    # Deduplicate by (keyword, cipher, alphabet)
    seen = set()
    unique_results = []
    for r in all_results:
        k = (r["keyword"], r["cipher"], r["alphabet"])
        if k not in seen:
            seen.add(k)
            unique_results.append(r)

    print()
    print("=" * 70)
    print(f"GRAND SUMMARY ({elapsed:.1f}s)")
    print("=" * 70)
    print(f"  Total unique configs tested: {len(seen)}")
    print(f"  Results with crib hits: {len(all_crib_hits)}")

    # Long crib hits (5+ chars)
    long_crib_hits = [r for r in all_crib_hits
                      if any(len(c) >= 5 for c, _ in r["crib_hits"])]
    if long_crib_hits:
        print(f"\n  *** LONG CRIB HITS (5+ char cribs) ***")
        for r in long_crib_hits[:20]:
            long_cribs = [(c, p) for c, p in r["crib_hits"] if len(c) >= 5]
            print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
                  f"key={r['keyword'][:30]} cribs={long_cribs}")
            print(f"             {r['plaintext'][:70]}")

    print(f"\n  Top 30 overall:")
    for r in unique_results[:30]:
        cribs = f" cribs={r['crib_hits']}" if r.get('crib_hits') else ""
        print(f"    {r['score']:>8.1f} {r['cipher']}/{r['alphabet']} "
              f"key={r['keyword'][:35]:<35} len={r['key_len']}{cribs}")

    # Save
    outfile = Path("results/e_grille_12_results.json")
    outfile.parent.mkdir(parents=True, exist_ok=True)
    save_data = {
        "experiment": "E-GRILLE-12",
        "target": "grille_extract_106",
        "elapsed_seconds": round(elapsed, 1),
        "total_unique_configs": len(seen),
        "crib_hits_count": len(all_crib_hits),
        "long_crib_hits_count": len(long_crib_hits),
        "top_50": [{k: v for k, v in r.items() if k != "plaintext"}
                   for r in unique_results[:50]],
        "all_crib_hits": [{k: v for k, v in r.items() if k != "plaintext"}
                          for r in all_crib_hits[:50]],
    }
    outfile.write_text(json.dumps(save_data, indent=2))
    print(f"\n  Saved to {outfile}")
    print()


if __name__ == "__main__":
    main()
