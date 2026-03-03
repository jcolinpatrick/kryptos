#!/usr/bin/env python3
"""
E-GRILLE-13: Field-executable ciphers taught by Kryptos K1-K3.

The progressive solve teaches:
  K1 → Vigenère/KA with keyword (PALIMPSEST)
  K2 → Vigenère/KA with keyword (ABSCISSA) + IDBYROWS hint
  K3 → Transposition/route cipher (grid reading)

Natural "next level" techniques — all hand-executable:
  1. AUTOKEY — PT or CT extends a short primer (non-periodic!)
  2. RUNNING KEY — K1/K2/K3 plaintext IS the key
  3. TRANSPOSITION — rearrange the extract using IDBYROWS-style grids
  4. TRANSPOSE THEN DECRYPT — undo grid first, then Vigenère
  5. NIHILIST — Polybius square + additive key (field tradecraft)
  6. BEAUFORT AUTOKEY — Beaufort variant of autokey
  7. GRONSFELD — numeric key (coordinates → digits → key)
"""

from __future__ import annotations
import json
import sys
import time
from pathlib import Path
from itertools import permutations
from multiprocessing import Pool, cpu_count

# ── Constants ────────────────────────────────────────────────────────────────

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
CT_LEN = 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# K1-K3 plaintexts (used as running keys)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENAMELESSLINEATIONPAINTINGMADEOFFLOWERSANDFADINGLIGHTWHOSEEVERYBLOOMDENIESTHEABEYANCEOFIDENTITYACROSSLIKEAREFLECTIONTHEFOLLOWINGPALEFLOSSINESSENDUREDITPERPETUITYFOREVERILLUSTRATINGTHATVISIBLECIPHERSPALEANDILLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYALWAYSWONDERHOWCOULDYOUHAVEGOTTENTHESEPICTURESITWASCLASSIFIEDPHOTOGRAPHYABSOLUTELYTOPSECRETPHOTOGRAPHYOFTHEMOSTSENSITIVEMILITARYINSTALLATIONSTHESOVIETUNIONWASOBSESSEDWITHRESTORINGADEADGERMANTOLIFEACROSSLIKEAREFLECTIONTHEFOLLOWINGPALEFLOSSINESSENDUREDITPERPETUITYFOREVERTHESECREATGALLERYWASCLOSEDAFTERTHATANDTHOSEINCREDIBLYRAREPHOTOGRAPHSTRANSMITTEDUNDERGROUNDTOANUNKNOWNLOCATIONIDBYROWS"
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISSHATENCRYPTEDINVISIBLEAIRWELLSANDMASTODONICSLIMERUSTTHEPLACINGOFTHEBONESBELOWTHEEARTHBELOWUNDERTHEMUNDANITYOFSTONESBELOWTWELVEMONKEYSBELOWBELOWCANYOUSEEANYTHINGQ"

CRIBS = [
    "EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLIN",
    "EAST", "NORTH", "CLOCK", "SHADOW", "LIGHT", "SLOWLY",
    "DESPERATELY", "INVISIBLE", "UNDERGROUND", "BURIED",
    "LAYER", "PALIMPSEST", "ABSCISSA", "KRYPTOS", "BETWEEN",
    "CARTER", "HOWARD", "PYRAMID", "DELIVER", "MESSAGE",
    "SECRET", "GALLERY", "PASSAGE", "BONES", "EARTH",
    "TWELVE", "MONKEYS", "CLASSIFIED", "PHOTOGRAPHS",
]

PRIMERS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "LIGHT",
    "EQUINOX", "BERLIN", "CLOCK", "EAST", "NORTH",
    "SANBORN", "SCHEIDT", "LOOMIS", "BOWEN", "LODESTONE",
    "COMPASS", "QUARTZ", "COPPER", "GRILLE", "CARDAN",
    "MASK", "LAYER", "FOLD", "YAR", "ILM", "LUX",
    "OFLNUXZ", "HILL", "IDBYROWS", "XLAYERTWO",
    "INVISIBLE", "BURIED", "SECRET", "HIDDEN", "PASSAGE",
    "KEY", "POSITION", "TABLEAU", "MERIDIAN", "AZIMUTH",
    "ENIGMA", "MEDUSA", "ANTIPODES", "VERDIGRIS",
    "WHIRLPOOL", "PETRIFIED", "METEORITE",
    "WEBSTER", "LANGLEY", "VIRGINIA", "MCLEAN",
    "EGYPT", "CARTER", "HOWARD", "SPHINX", "PYRAMID",
    "WELTZEITUHR", "ALEXANDERPLATZ",
]

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

def evaluate(pt: str, method: str, detail: str) -> dict | None:
    sc = score_text(pt)
    crib_hits = has_cribs(pt)
    if crib_hits or sc > -700:
        return {
            "method": method, "detail": detail,
            "score": sc, "plaintext": pt, "crib_hits": crib_hits,
        }
    return None


# ── 1. AUTOKEY (PT-autokey and CT-autokey) ───────────────────────────────────

def autokey_pt_decrypt(ct: str, primer: str, alpha: str) -> str:
    """PT-autokey Vigenère: key = primer + plaintext."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ci - ki) % 26]
        pt.append(p)
        key.append(p)  # extend key with plaintext
    return "".join(pt)

def autokey_ct_decrypt(ct: str, primer: str, alpha: str) -> str:
    """CT-autokey Vigenère: key = primer + ciphertext."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ci - ki) % 26]
        pt.append(p)
        key.append(c)  # extend key with ciphertext
    return "".join(pt)

def autokey_pt_beau(ct: str, primer: str, alpha: str) -> str:
    """PT-autokey Beaufort."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ki - ci) % 26]
        pt.append(p)
        key.append(p)
    return "".join(pt)

def autokey_ct_beau(ct: str, primer: str, alpha: str) -> str:
    """CT-autokey Beaufort."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ki - ci) % 26]
        pt.append(p)
        key.append(c)
    return "".join(pt)

def attack_autokey() -> list[dict]:
    print("=" * 70)
    print("ATTACK 1: Autokey (PT-autokey, CT-autokey, Vig + Beau)")
    print(f"  Primers: {len(PRIMERS)} | Variants: 4 | Alphabets: 2")
    print("=" * 70)
    results = []

    for primer in PRIMERS:
        primer = primer.upper()
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            if not all(c in alpha for c in primer):
                continue
            for name, fn in [
                ("autokey_pt_vig", autokey_pt_decrypt),
                ("autokey_ct_vig", autokey_ct_decrypt),
                ("autokey_pt_beau", autokey_pt_beau),
                ("autokey_ct_beau", autokey_ct_beau),
            ]:
                try:
                    pt = fn(GRILLE_CT, primer, alpha)
                except (ValueError, IndexError):
                    continue
                r = evaluate(pt, name, f"primer={primer} alpha={alpha_name}")
                if r:
                    results.append(r)

    results.sort(key=lambda r: -r["score"])
    _print_top(results, "Autokey")
    return results


# ── 2. RUNNING KEY from K1/K2/K3 plaintext ──────────────────────────────────

def running_key_decrypt(ct: str, key_text: str, alpha: str, offset: int = 0) -> str:
    """Vigenère decrypt using running key starting at offset."""
    result = []
    for i, c in enumerate(ct):
        ki = alpha.index(key_text[(i + offset) % len(key_text)])
        ci = alpha.index(c)
        result.append(alpha[(ci - ki) % 26])
    return "".join(result)

def running_key_beau(ct: str, key_text: str, alpha: str, offset: int = 0) -> str:
    """Beaufort decrypt using running key starting at offset."""
    result = []
    for i, c in enumerate(ct):
        ki = alpha.index(key_text[(i + offset) % len(key_text)])
        ci = alpha.index(c)
        result.append(alpha[(ki - ci) % 26])
    return "".join(result)

def attack_running_key() -> list[dict]:
    print("=" * 70)
    print("ATTACK 2: Running key from K1/K2/K3 plaintext")
    print("=" * 70)
    results = []

    for key_name, key_text in [("K1_PT", K1_PT), ("K2_PT", K2_PT), ("K3_PT", K3_PT)]:
        # Try different offsets into the plaintext
        max_offset = len(key_text) - CT_LEN
        offsets = list(range(0, max(1, max_offset), 1))  # every position

        for offset in offsets:
            for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
                for cipher_name, cipher_fn in [
                    ("running_vig", running_key_decrypt),
                    ("running_beau", running_key_beau),
                ]:
                    try:
                        pt = cipher_fn(GRILLE_CT, key_text, alpha, offset)
                    except (ValueError, IndexError):
                        continue
                    r = evaluate(pt, cipher_name, f"key={key_name} offset={offset} alpha={alpha_name}")
                    if r:
                        results.append(r)

    # Also: K1+K2+K3 concatenated
    combined_pt = K1_PT + K2_PT + K3_PT
    for offset in range(0, len(combined_pt) - CT_LEN, 10):
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            for cipher_name, cipher_fn in [
                ("running_vig", running_key_decrypt),
                ("running_beau", running_key_beau),
            ]:
                try:
                    pt = cipher_fn(GRILLE_CT, combined_pt, alpha, offset)
                except (ValueError, IndexError):
                    continue
                r = evaluate(pt, cipher_name, f"key=K123_combined offset={offset} alpha={alpha_name}")
                if r:
                    results.append(r)

    results.sort(key=lambda r: -r["score"])
    _print_top(results, "Running key")
    return results


# ── 3. TRANSPOSITION — rearrange extract, then check for English ────────────

def columnar_read(text: str, width: int, key_perm: tuple) -> str:
    """Write text into grid by rows, read out by columns in key order."""
    nrows = -(-len(text) // width)
    # Pad if needed
    padded = text + "X" * (nrows * width - len(text))
    # Write into grid by rows
    grid = [padded[i*width:(i+1)*width] for i in range(nrows)]
    # Read columns in key order
    result = []
    for col in key_perm:
        for row in grid:
            if col < len(row):
                result.append(row[col])
    return "".join(result)[:len(text)]

def columnar_unwrite(text: str, width: int, key_perm: tuple) -> str:
    """Undo columnar transposition: text was written by columns in key order, read by rows."""
    nrows = -(-len(text) // width)
    n_long = len(text) - width * (nrows - 1)

    # Figure out column lengths based on key order
    col_lengths = [nrows if key_perm[c] < n_long else nrows - 1 for c in range(width)]

    # Split text into columns (in key order)
    cols_in_order = []
    pos = 0
    for cl in col_lengths:
        cols_in_order.append(text[pos:pos+cl])
        pos += cl

    # Place columns into correct position
    ordered = [""] * width
    for i, col_idx in enumerate(key_perm):
        ordered[col_idx] = cols_in_order[i]

    # Read by rows
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(ordered[col]):
                result.append(ordered[col][row])
    return "".join(result)

def attack_transposition() -> list[dict]:
    print("=" * 70)
    print("ATTACK 3: Transposition (rearrange, then check for words/cribs)")
    print("=" * 70)
    results = []

    # Try columnar transposition with various widths
    # Both directions: write-by-rows/read-by-cols AND undo (write-by-cols/read-by-rows)
    for width in range(2, 12):
        n_perms = 1
        for i in range(1, width + 1):
            n_perms *= i
        if n_perms > 5_000_000:
            continue

        for perm in permutations(range(width)):
            # Direction 1: text was written by rows, read by columns
            try:
                pt = columnar_read(GRILLE_CT, width, perm)
            except:
                continue
            r = evaluate(pt, "trans_read_cols", f"w={width} perm={perm}")
            if r:
                results.append(r)

            # Direction 2: undo columnar (text was columnar-encrypted)
            try:
                pt = columnar_unwrite(GRILLE_CT, width, perm)
            except:
                continue
            r = evaluate(pt, "trans_unwrite", f"w={width} perm={perm}")
            if r:
                results.append(r)

    # Also: simple row reversal, column reversal at various widths
    for width in [7, 8, 9, 10, 11, 14, 53]:
        # Read by columns (no permutation — identity)
        nrows = -(-CT_LEN // width)
        grid = []
        for i in range(0, CT_LEN, width):
            grid.append(GRILLE_CT[i:i+width])

        # Column-major reading
        col_read = []
        for c in range(width):
            for row in grid:
                if c < len(row):
                    col_read.append(row[c])
        pt = "".join(col_read)
        r = evaluate(pt, "col_major", f"w={width}")
        if r:
            results.append(r)

        # Reverse each row
        rev_rows = "".join(row[::-1] for row in grid)
        r = evaluate(rev_rows, "rev_rows", f"w={width}")
        if r:
            results.append(r)

    # Rail fence
    for rails in range(2, 10):
        fence = [[] for _ in range(rails)]
        rail, direction = 0, 1
        for c in GRILLE_CT:
            fence[rail].append(c)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        pt = "".join("".join(f) for f in fence)
        r = evaluate(pt, "rail_fence_enc", f"rails={rails}")
        if r:
            results.append(r)

        # Also undo rail fence
        lengths = [0] * rails
        rail, direction = 0, 1
        for _ in GRILLE_CT:
            lengths[rail] += 1
            if rail == 0: direction = 1
            elif rail == rails - 1: direction = -1
            rail += direction

        idx = 0
        fence2 = []
        for length in lengths:
            fence2.append(list(GRILLE_CT[idx:idx+length]))
            idx += length

        result = []
        iters = [iter(f) for f in fence2]
        rail, direction = 0, 1
        for _ in range(CT_LEN):
            result.append(next(iters[rail]))
            if rail == 0: direction = 1
            elif rail == rails - 1: direction = -1
            rail += direction
        pt = "".join(result)
        r = evaluate(pt, "rail_fence_dec", f"rails={rails}")
        if r:
            results.append(r)

    results.sort(key=lambda r: -r["score"])
    _print_top(results, "Transposition")
    return results


# ── 4. TRANSPOSE THEN DECRYPT ───────────────────────────────────────────────

def _transpose_then_decrypt_worker(args: tuple) -> list[dict]:
    """Worker: columnar unscramble → autokey/vig decrypt."""
    width, perms_chunk = args
    _load_quadgrams()
    results = []

    for perm in perms_chunk:
        # Undo columnar transposition
        try:
            unscrambled = columnar_unwrite(GRILLE_CT, width, perm)
        except:
            continue

        # Now try Vigenère/Beaufort/Autokey with short primers
        for primer in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "EQUINOX",
                        "SANBORN", "SCHEIDT", "SHADOW", "LIGHT"]:
            for alpha_name, alpha in [("KA", KA)]:
                if not all(c in alpha for c in primer):
                    continue

                # Periodic Vigenère
                pt = "".join(alpha[(alpha.index(c) - alpha.index(primer[i % len(primer)])) % 26]
                             for i, c in enumerate(unscrambled))
                r = evaluate(pt, "trans+vig", f"w={width} perm={perm[:5]}... primer={primer}")
                if r:
                    results.append(r)

                # PT-autokey
                pt_ak = []
                key = list(primer)
                for i, c in enumerate(unscrambled):
                    ki = alpha.index(key[i])
                    ci = alpha.index(c)
                    p = alpha[(ci - ki) % 26]
                    pt_ak.append(p)
                    key.append(p)
                pt = "".join(pt_ak)
                r = evaluate(pt, "trans+autokey", f"w={width} perm={perm[:5]}... primer={primer}")
                if r:
                    results.append(r)

    return results

def attack_transpose_then_decrypt() -> list[dict]:
    print("=" * 70)
    print("ATTACK 4: Transpose THEN decrypt (undo grid, then Vig/Autokey)")
    print("=" * 70)
    results = []
    workers = min(cpu_count(), 28)

    for width in range(2, 9):  # Up to 8 (8! = 40320)
        all_perms = list(permutations(range(width)))
        chunk_size = max(1, len(all_perms) // (workers * 4))
        chunks = [(width, all_perms[i:i+chunk_size])
                  for i in range(0, len(all_perms), chunk_size)]

        print(f"  Width {width}: {len(all_perms)} perms × 8 primers × 2 methods = "
              f"{len(all_perms) * 16} configs")

        with Pool(workers) as pool:
            for batch in pool.imap_unordered(_transpose_then_decrypt_worker, chunks):
                results.extend(batch)

    results.sort(key=lambda r: -r["score"])
    _print_top(results, "Transpose+Decrypt")
    return results


# ── 5. NIHILIST CIPHER ──────────────────────────────────────────────────────

def make_polybius(keyword: str, alpha: str = AZ) -> dict[str, str]:
    """Create a 5×5 Polybius square (I/J merged or custom)."""
    # For 26-letter KA, use 6×5 or skip
    if len(alpha) == 26:
        # Standard: merge I/J for 5×5
        merged = ""
        seen = set()
        for c in keyword.upper() + alpha:
            if c == 'J':
                c = 'I'
            if c not in seen:
                seen.add(c)
                merged += c
        mapping = {}
        for idx, c in enumerate(merged[:25]):
            row, col = divmod(idx, 5)
            mapping[c] = str(row + 1) + str(col + 1)
        mapping['J'] = mapping.get('I', '24')
        return mapping
    return {}

def nihilist_decrypt(ct: str, keyword: str, key_text: str) -> str:
    """Nihilist cipher decrypt: CT digits - key digits → Polybius → PT."""
    poly = make_polybius(keyword)
    if not poly:
        return ""
    inv_poly = {v: k for k, v in poly.items()}

    # Convert key to digit pairs
    key_digits = []
    for c in key_text.upper():
        if c in poly:
            key_digits.append(int(poly[c]))

    if not key_digits:
        return ""

    # CT must be numeric pairs — but our CT is alphabetic
    # Nihilist usually produces numeric CT, so this might not apply
    # Instead, try: interpret CT letters as Polybius lookups
    ct_digits = []
    for c in ct.upper():
        if c in poly:
            ct_digits.append(int(poly[c]))
        else:
            ct_digits.append(0)

    # Subtract key
    result = []
    for i, cd in enumerate(ct_digits):
        kd = key_digits[i % len(key_digits)]
        diff = cd - kd
        # Nihilist: result should be a valid 2-digit Polybius code (11-55)
        ds = str(abs(diff))
        if len(ds) == 2 and ds in inv_poly:
            result.append(inv_poly[ds])
        elif len(ds) == 1:
            ds = "0" + ds
            if ds in inv_poly:
                result.append(inv_poly[ds])
            else:
                result.append("?")
        else:
            result.append("?")

    return "".join(result)

def attack_nihilist() -> list[dict]:
    print("=" * 70)
    print("ATTACK 5: Nihilist cipher (Polybius + additive key)")
    print("=" * 70)
    results = []

    square_keywords = ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "SHADOW",
                        "EQUINOX", "BERLIN", "SCHEIDT", "SANBORN"]
    key_texts = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "EQUINOX",
                  "BERLIN", "SCHEIDT", "SANBORN", "LOOMIS", "LODESTONE"]

    for sq_kw in square_keywords:
        for kt in key_texts:
            pt = nihilist_decrypt(GRILLE_CT, sq_kw, kt)
            if "?" * 5 not in pt:  # skip if too many unknowns
                r = evaluate(pt, "nihilist", f"square={sq_kw} key={kt}")
                if r:
                    results.append(r)

    results.sort(key=lambda r: -r["score"])
    _print_top(results, "Nihilist")
    return results


# ── 6. GRONSFELD (numeric Vigenère) ─────────────────────────────────────────

def gronsfeld_decrypt(ct: str, num_key: list[int], alpha: str) -> str:
    return "".join(alpha[(alpha.index(c) - num_key[i % len(num_key)]) % 26]
                   for i, c in enumerate(ct))

def attack_gronsfeld() -> list[dict]:
    print("=" * 70)
    print("ATTACK 6: Gronsfeld (numeric keys from coordinates/dates)")
    print("=" * 70)
    results = []

    numeric_keys = [
        ("LOOMIS_lat", [3, 8, 5, 7, 0, 6, 2, 2]),
        ("LOOMIS_lon", [0, 7, 7, 0, 8, 4, 8, 1, 4]),
        ("LOOMIS_combined", [3, 8, 5, 7, 0, 6, 2, 2, 0, 7, 7, 0, 8, 4, 8, 1, 4]),
        ("K2_lat", [3, 8, 5, 7, 6, 5]),
        ("K2_lon", [7, 7, 8, 4, 4]),
        ("K2_combined", [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]),
        ("year_1989", [1, 9, 8, 9]),
        ("year_1990", [1, 9, 9, 0]),
        ("year_1986", [1, 9, 8, 6]),
        ("dates_both", [1, 9, 8, 6, 1, 9, 8, 9]),  # Egypt 1986, Berlin 1989
        ("K4_len", [9, 7]),
        ("webster_tenure", [4, 9, 7]),  # 4 years + 97 days
        ("K4_97_prime", [9, 7]),
        ("weltzeituhr_24", [2, 4]),
        ("eight_lines_73", [8, 7, 3]),
        ("eleven_lines_342", [1, 1, 3, 4, 2]),
    ]

    for name, key in numeric_keys:
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            pt = gronsfeld_decrypt(GRILLE_CT, key, alpha)
            r = evaluate(pt, "gronsfeld", f"key={name}={key} alpha={alpha_name}")
            if r:
                results.append(r)

            # Also reversed key
            pt = gronsfeld_decrypt(GRILLE_CT, key[::-1], alpha)
            r = evaluate(pt, "gronsfeld_rev", f"key={name}_rev alpha={alpha_name}")
            if r:
                results.append(r)

    results.sort(key=lambda r: -r["score"])
    _print_top(results, "Gronsfeld")
    return results


# ── Utility ──────────────────────────────────────────────────────────────────

def _print_top(results: list[dict], label: str, n: int = 15):
    crib_hits = [r for r in results if r.get("crib_hits")]
    print(f"\n  Results: {len(results)} | With cribs: {len(crib_hits)}")

    if crib_hits:
        print(f"  *** CRIB HITS ***")
        for r in crib_hits[:10]:
            print(f"    {r['score']:>8.1f} [{r['method']}] {r['detail'][:50]}")
            print(f"             cribs={r['crib_hits']}")
            print(f"             {r['plaintext'][:70]}")

    print(f"  Top {min(n, len(results))} by score:")
    for r in results[:n]:
        cribs = f" cribs={r['crib_hits']}" if r.get('crib_hits') else ""
        print(f"    {r['score']:>8.1f} [{r['method']}] {r['detail'][:55]}{cribs}")
    print()


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    print()
    print("#" * 70)
    print("#  E-GRILLE-13: Field-executable ciphers taught by K1-K3")
    print("#  CT: Cardan grille extract (106 chars)")
    print("#" * 70)
    print()
    print(f"  CT: {GRILLE_CT}")
    print(f"  K1-K3 keywords: PALIMPSEST, ABSCISSA, KRYPTOS")
    print(f"  Progressive solve: each section teaches the next technique")
    print()

    _load_quadgrams()
    t0 = time.time()

    r1 = attack_autokey()
    r2 = attack_running_key()
    r3 = attack_transposition()
    r4 = attack_transpose_then_decrypt()
    r5 = attack_nihilist()
    r6 = attack_gronsfeld()

    elapsed = time.time() - t0

    all_results = r1 + r2 + r3 + r4 + r5 + r6
    all_results.sort(key=lambda r: -r["score"])

    all_cribs = [r for r in all_results if r.get("crib_hits")]
    long_cribs = [r for r in all_cribs if any(len(c) >= 6 for c, _ in r["crib_hits"])]

    print()
    print("=" * 70)
    print(f"GRAND SUMMARY ({elapsed:.1f}s)")
    print("=" * 70)
    print(f"  Total results above threshold: {len(all_results)}")
    print(f"  With crib hits: {len(all_cribs)}")
    print(f"  With long cribs (6+): {len(long_cribs)}")

    if long_cribs:
        print(f"\n  *** LONG CRIB HITS ***")
        for r in long_cribs[:15]:
            lc = [(c, p) for c, p in r["crib_hits"] if len(c) >= 6]
            print(f"    {r['score']:>8.1f} [{r['method']}] {r['detail'][:50]}")
            print(f"             cribs={lc}")
            print(f"             {r['plaintext'][:70]}")

    print(f"\n  Top 25 overall:")
    for r in all_results[:25]:
        cribs = f" {r['crib_hits']}" if r.get('crib_hits') else ""
        print(f"    {r['score']:>8.1f} [{r['method']}] {r['detail'][:55]}{cribs}")

    outfile = Path("results/e_grille_13_results.json")
    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(json.dumps({
        "experiment": "E-GRILLE-13",
        "elapsed_seconds": round(elapsed, 1),
        "total_results": len(all_results),
        "crib_hits": len(all_cribs),
        "long_crib_hits": len(long_cribs),
        "top_30": [{k: v for k, v in r.items() if k != "plaintext"}
                   for r in all_results[:30]],
    }, indent=2))
    print(f"\n  Saved to {outfile}")
    print()


if __name__ == "__main__":
    main()
