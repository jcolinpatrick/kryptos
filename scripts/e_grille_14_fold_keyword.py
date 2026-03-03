#!/usr/bin/env python3
"""
E-GRILLE-14: Derive the keyword from the FOLD itself.

PHYSICAL PROTOCOL:
  1. Transcribe both sides of the Kryptos sculpture
  2. Fold cipher side onto tableau side (direct overlay)
  3. Hold to light — grille holes reveal 106 tableau characters
  4. But ALSO: the cipher-side characters at those SAME hole positions
     show through too. THOSE characters may be the keyword.

The keyword comes FROM THE PROCESS, not from external knowledge.

Tests:
  A. Map grille hole positions → cipher-side characters → use as keyword
  B. Map grille hole positions → cipher-side PLAINTEXT (decoded K1-K3) → keyword
  C. Letters on cipher side at grille holes, in various reading orders
  D. Progressive: K1 solution teaches PALIMPSEST → fold → grille → keyword
  E. What the SOLVED K3 text says at grille positions (K3 is on cipher side)
  F. Row labels where holes appear (the tableau row shifts)
"""

from __future__ import annotations
import json
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
CT_LEN = 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Full cipher side text (28 rows × ~33 chars, from the sculpture)
# Rows as they appear, including ? marks
CIPHER_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",   # Row 1
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",    # Row 2
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",     # Row 3
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",      # Row 4
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",      # Row 5
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",    # Row 6
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",      # Row 7
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",     # Row 8
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",    # Row 9
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",     # Row 10
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",       # Row 11
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",      # Row 12
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",      # Row 13
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",      # Row 14
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA",     # Row 15  (K3 starts)
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",       # Row 16
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",       # Row 17
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",        # Row 18
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",     # Row 19
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",        # Row 20
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",     # Row 21
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",      # Row 22
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",    # Row 23
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",         # Row 24
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",      # Row 25  (K4 starts mid-row)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",       # Row 26
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",       # Row 27
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",      # Row 28
]

# Grille mask (28 rows × 33 cols, 0=hole, 1=masked, ~=off-grid)
MASK_ROWS = [
    "000000001010100000000010000000001~~",   # Row 1
    "100000000010000001000100110000011~~",   # Row 2
    "000000000000001000000000000000011~~",   # Row 3
    "00000000000000000000100000010011~~",    # Row 4
    "00000001000000001000010000000011~~",    # Row 5
    "000000001000000000000000000000011~",    # Row 6
    "100000000000000000000000000000011",     # Row 7
    "00000000000000000000000100000100~~",    # Row 8
    "0000000000000000000100000001000~~",     # Row 9
    "0000000000000000000000000000100~~",     # Row 10
    "000000001000000000000000000000~~",      # Row 11
    "00000110000000000000000000000100~~",    # Row 12
    "00000000000000100010000000000001~~",    # Row 13
    "00000000000100000000000000001000~~",    # Row 14
    "000110100001000000000000001000010~~",   # Row 15
    "00001010000000000000000001000001~~",    # Row 16
    "001001000010010000000000000100010~~",   # Row 17
    "00000000000100000000010000010001~~",    # Row 18
    "000000000000010001001000000010001~~",   # Row 19
    "00000000000000001001000000000100~~",    # Row 20
    "000000001100000010100100010001001~~",   # Row 21
    "000000000000000100001010100100011~",    # Row 22
    "00000000100000000000100001100001~~~",   # Row 23
    "100000000000000000001000001000010~",    # Row 24
    "10000001000001000000100000000001~~",    # Row 25
    "000010000000000000010000100000011",     # Row 26
    "0000000000000000000100001000000011",    # Row 27
    "00000000000000100000001010000001~~",    # Row 28
]

# K3 plaintext (written into the K3 area of the cipher side)
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISSHATENCRYPTEDINVISIBLEAIRWELLSANDMASTODONICSLIMERUSTTHEPLACINGOFTHEBONESBELOWTHEEARTHBELOWUNDERTHEMUNDANITYOFSTONESBELOWTWELVEMONKEYSBELOWBELOWCANYOUSEEANYTHINGQ"

# K1 + K2 plaintext
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENAMELESSLINEATIONPAINTINGMADEOFFLOWERSANDFADINGLIGHTWHOSEEVERYBLOOMDENIESTHEABEYANCEOFIDENTITYACROSSLIKEAREFLECTIONTHEFOLLOWINGPALEFLOSSINESSENDUREDITPERPETUITYFOREVERILLUSTRATINGTHATVISIBLECIPHERSPALEANDILLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYALWAYSWONDERHOWCOULDYOUHAVEGOTTENTHESEPICTURESITWASCLASSIFIEDPHOTOGRAPHYABSOLUTELYTOPSECRETPHOTOGRAPHYOFTHEMOSTSENSITIVEMILITARYINSTALLATIONSTHESOVIETUNIONWASOBSESSEDWITHRESTORINGADEADGERMANTOLIFEACROSSLIKEAREFLECTIONTHEFOLLOWINGPALEFLOSSINESSENDUREDITPERPETUITYFOREVERTHESECREATGALLERYWASCLOSEDAFTERTHATANDTHOSEINCREDIBLYRAREPHOTOGRAPHSTRANSMITTEDUNDERGROUNDTOANUNKNOWNLOCATIONIDBYROWS"

CRIBS = [
    "EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLIN",
    "EAST", "NORTH", "CLOCK", "SHADOW", "LIGHT", "SLOWLY",
    "BURIED", "LAYER", "PASSAGE", "SECRET", "INVISIBLE",
    "BETWEEN", "PALIMPSEST", "ABSCISSA",
    # Non-K4 cribs — the grille message might say something different
    "FOLD", "HOLD", "READ", "MASK", "GRILLE", "POSITION",
    "KEYWORD", "CIPHER", "DECODE", "REVEAL", "HIDDEN",
    "TECHNIQUE", "METHOD", "INSTRUCTIONS",
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
    if not qg: return 0.0
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
                   for i, c in enumerate(ct) if c in alpha)

def beau_decrypt(ct: str, key: str, alpha: str) -> str:
    return "".join(alpha[(alpha.index(key[i % len(key)]) - alpha.index(c)) % 26]
                   for i, c in enumerate(ct) if c in alpha)

def autokey_pt_decrypt(ct: str, primer: str, alpha: str) -> str:
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        if c not in alpha: continue
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ci - ki) % 26]
        pt.append(p)
        key.append(p)
    return "".join(pt)

def autokey_ct_decrypt(ct: str, primer: str, alpha: str) -> str:
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        if c not in alpha: continue
        ki = alpha.index(key[i])
        ci = alpha.index(c)
        p = alpha[(ci - ki) % 26]
        pt.append(p)
        key.append(c)
    return "".join(pt)


# ── Extract cipher-side characters at grille positions ──────────────────────

def get_hole_positions() -> list[tuple[int, int]]:
    """Get all (row, col) positions of holes in the grille mask."""
    holes = []
    for row_idx, mask in enumerate(MASK_ROWS):
        for col_idx, c in enumerate(mask):
            if c == '1':  # 1=hole (visible), 0=masked — documentation had inverted convention
                holes.append((row_idx, col_idx))
    return holes

def get_cipher_side_at_holes() -> tuple[str, list[tuple[int, int, str]]]:
    """Get the cipher-side characters at each grille hole position."""
    holes = get_hole_positions()
    chars = []
    details = []

    for row, col in holes:
        if row < len(CIPHER_ROWS) and col < len(CIPHER_ROWS[row]):
            c = CIPHER_ROWS[row][col]
            chars.append(c)
            details.append((row, col, c))
        else:
            chars.append("~")
            details.append((row, col, "~"))

    return "".join(chars), details


def get_plaintext_at_holes() -> str:
    """Get the DECODED plaintext at each grille hole position.

    This requires knowing which section each hole falls in and
    applying the appropriate decryption.
    """
    # Build the full cipher-side as one string, row by row
    full_cipher = ""
    for row in CIPHER_ROWS:
        full_cipher += row

    # Build the full plaintext (K1+K2+K3+K4_unknown)
    # K1: rows 1-? K2: rows ?-? K3: rows 15-25 K4: rows 25-28
    # We know K1, K2, K3 plaintexts. K4 is unknown.
    # For simplicity, concatenate known PT in order
    # K1 starts at position 0 in the cipher text
    # K2 starts after K1 (63 chars)
    # K3 starts at row 15 (ENDYAHR...)
    # K4 starts at OBKR...

    # Actually, let's just map positions directly
    # K1 CT = positions 0-62 (63 chars)
    # K2 CT = positions 63-431 (369 chars, including ? marks)
    # K3 CT = positions 432-767 (336 chars)
    # K4 CT = positions 768-864 (97 chars)

    # For holes, we need their linear position in the full text
    holes = get_hole_positions()
    result = []

    for row, col in holes:
        # Linear position
        linear_pos = sum(len(CIPHER_ROWS[r]) for r in range(row)) + col
        if linear_pos < 63:
            # K1 section
            if linear_pos < len(K1_PT):
                result.append(K1_PT[linear_pos])
            else:
                result.append("?")
        elif linear_pos < 432:
            # K2 section
            k2_pos = linear_pos - 63
            if k2_pos < len(K2_PT):
                result.append(K2_PT[k2_pos])
            else:
                result.append("?")
        elif linear_pos < 768:
            # K3 section
            k3_pos = linear_pos - 432
            if k3_pos < len(K3_PT):
                result.append(K3_PT[k3_pos])
            else:
                result.append("?")
        else:
            # K4 section — unknown
            result.append("*")

    return "".join(result)


# ── Main tests ──────────────────────────────────────────────────────────────

def main():
    print()
    print("#" * 70)
    print("#  E-GRILLE-14: Derive keyword from the FOLD itself")
    print("#  The keyword comes from the PROCESS, not external knowledge")
    print("#" * 70)
    print()

    _load_quadgrams()
    holes = get_hole_positions()
    print(f"  Total grille holes: {len(holes)}")
    print(f"  Grille extract (106 chars): {GRILLE_CT}")
    print()

    # ── A: Cipher-side characters at hole positions ─────────────────────
    print("=" * 70)
    print("TEST A: Cipher-side characters at grille hole positions")
    print("  (What shows through from the OTHER side when you fold)")
    print("=" * 70)

    cipher_key, details = get_cipher_side_at_holes()
    print(f"\n  Cipher-side through holes ({len(cipher_key)} chars):")
    print(f"  {cipher_key}")
    print()

    # Clean (remove ? marks)
    cipher_key_clean = cipher_key.replace("?", "")
    print(f"  Cleaned (no ?): {cipher_key_clean} ({len(cipher_key_clean)} chars)")

    # Show by row
    print(f"\n  By row:")
    current_row = -1
    for row, col, c in details:
        if row != current_row:
            if current_row >= 0:
                print()
            print(f"    Row {row+1:>2}: ", end="")
            current_row = row
        print(c, end="")
    print("\n")

    # Use as keyword (full, first N chars, unique chars)
    key_variants = {
        "full": cipher_key_clean,
        "first_7": cipher_key_clean[:7],
        "first_8": cipher_key_clean[:8],
        "first_10": cipher_key_clean[:10],
        "first_12": cipher_key_clean[:12],
        "unique_ordered": "".join(dict.fromkeys(cipher_key_clean)),  # deduplicated, order preserved
    }

    print("  Decryption attempts with cipher-side key variants:")
    for variant_name, key in key_variants.items():
        if len(key) < 2:
            continue
        print(f"\n  Key variant: {variant_name} = '{key}' (len={len(key)})")
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            if not all(c in alpha for c in key):
                print(f"    {alpha_name}: key contains invalid chars, skipping")
                continue
            for cipher_name, cipher_fn in [
                ("vig", vig_decrypt), ("beau", beau_decrypt),
                ("autokey_pt", autokey_pt_decrypt), ("autokey_ct", autokey_ct_decrypt),
            ]:
                pt = cipher_fn(GRILLE_CT, key, alpha)
                sc = score_text(pt)
                cribs = has_cribs(pt)
                marker = " ***" if sc > -700 or cribs else ""
                crib_str = f" CRIBS={cribs}" if cribs else ""
                print(f"    {cipher_name}/{alpha_name}: score={sc:>8.1f}{crib_str}{marker}")
                if sc > -800 or cribs:
                    print(f"      PT: {pt[:70]}")

    # ── B: Decoded plaintext at hole positions ──────────────────────────
    print()
    print("=" * 70)
    print("TEST B: DECODED plaintext at grille hole positions")
    print("  (K1/K2/K3 solutions read through the holes)")
    print("=" * 70)

    pt_key = get_plaintext_at_holes()
    print(f"\n  Plaintext through holes ({len(pt_key)} chars):")
    print(f"  {pt_key}")
    k4_count = pt_key.count("*")
    print(f"  (* = K4 unknown positions: {k4_count})")
    print()

    # Use known-only portion as key
    known_pt = pt_key.replace("*", "").replace("?", "")
    print(f"  Known plaintext key: {known_pt} ({len(known_pt)} chars)")

    key_variants_pt = {
        "full_known": known_pt,
        "first_7": known_pt[:7],
        "first_8": known_pt[:8],
        "first_10": known_pt[:10],
        "first_12": known_pt[:12],
    }

    print("\n  Decryption attempts with plaintext-derived key variants:")
    for variant_name, key in key_variants_pt.items():
        if len(key) < 2:
            continue
        key = key.upper()
        print(f"\n  Key variant: {variant_name} = '{key[:30]}...' (len={len(key)})")
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            if not all(c in alpha for c in key):
                continue
            for cipher_name, cipher_fn in [
                ("vig", vig_decrypt), ("beau", beau_decrypt),
                ("autokey_pt", autokey_pt_decrypt), ("autokey_ct", autokey_ct_decrypt),
            ]:
                pt = cipher_fn(GRILLE_CT, key, alpha)
                sc = score_text(pt)
                cribs = has_cribs(pt)
                marker = " ***" if sc > -700 or cribs else ""
                crib_str = f" CRIBS={cribs}" if cribs else ""
                print(f"    {cipher_name}/{alpha_name}: score={sc:>8.1f}{crib_str}{marker}")
                if sc > -800 or cribs:
                    print(f"      PT: {pt[:70]}")

    # ── C: Row labels where holes appear ────────────────────────────────
    print()
    print("=" * 70)
    print("TEST C: Tableau row labels at hole positions")
    print("  (Each row of the KA tableau starts with a specific letter)")
    print("=" * 70)

    # KA alphabet row labels (28 rows = 26 + wrap)
    row_labels = KA + KA[:2]  # 28 rows
    row_key = "".join(row_labels[h[0]] for h in holes)
    print(f"\n  Row label key ({len(row_key)} chars): {row_key[:60]}...")

    # But more useful: which UNIQUE rows have holes, in order of first appearance
    seen_rows = []
    for h in holes:
        label = row_labels[h[0]]
        if label not in seen_rows:
            seen_rows.append(label)
    unique_row_key = "".join(seen_rows)
    print(f"  Unique row labels (first appearance): {unique_row_key} ({len(unique_row_key)} chars)")

    # Holes per row
    print(f"\n  Holes per row:")
    for row_idx in range(28):
        row_holes = [h for h in holes if h[0] == row_idx]
        if row_holes:
            cols = [h[1] for h in row_holes]
            print(f"    Row {row_idx+1:>2} ({row_labels[row_idx]}): "
                  f"{len(row_holes)} holes at cols {cols}")

    # ── D: Column indices as keyword ────────────────────────────────────
    print()
    print("=" * 70)
    print("TEST D: Column indices of first hole per row as keyword")
    print("=" * 70)

    first_hole_per_row = {}
    for row, col in holes:
        if row not in first_hole_per_row:
            first_hole_per_row[row] = col

    col_indices = [first_hole_per_row[r] for r in sorted(first_hole_per_row.keys())]
    # Convert to letters: col 0 = A, col 1 = B, etc.
    col_key_az = "".join(AZ[c % 26] for c in col_indices)
    col_key_ka = "".join(KA[c % 26] for c in col_indices)
    print(f"  First hole column per row: {col_indices}")
    print(f"  As AZ key: {col_key_az}")
    print(f"  As KA key: {col_key_ka}")

    for key_name, key in [("col_AZ", col_key_az), ("col_KA", col_key_ka)]:
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            if not all(c in alpha for c in key):
                continue
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt),
                                            ("autokey_pt", autokey_pt_decrypt)]:
                pt = cipher_fn(GRILLE_CT, key, alpha)
                sc = score_text(pt)
                cribs = has_cribs(pt)
                marker = " ***" if sc > -700 or cribs else ""
                crib_str = f" CRIBS={cribs}" if cribs else ""
                print(f"    {cipher_name}/{alpha_name} key={key_name}: score={sc:>8.1f}{crib_str}{marker}")
                if sc > -800 or cribs:
                    print(f"      PT: {pt[:70]}")

    # ── E: Hole COUNT per row as numeric key (Gronsfeld) ────────────────
    print()
    print("=" * 70)
    print("TEST E: Hole count per row as Gronsfeld key")
    print("=" * 70)

    hole_counts = []
    for row_idx in range(28):
        count = sum(1 for h in holes if h[0] == row_idx)
        hole_counts.append(count)
    print(f"  Holes per row: {hole_counts}")
    print(f"  As digits: {''.join(str(c % 10) for c in hole_counts)}")

    # Gronsfeld decrypt
    for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
        pt = "".join(alpha[(alpha.index(c) - hole_counts[i % 28]) % 26]
                     for i, c in enumerate(GRILLE_CT))
        sc = score_text(pt)
        cribs = has_cribs(pt)
        marker = " ***" if sc > -700 or cribs else ""
        crib_str = f" CRIBS={cribs}" if cribs else ""
        print(f"    gronsfeld/{alpha_name}: score={sc:>8.1f}{crib_str}{marker}")
        if sc > -800 or cribs:
            print(f"      PT: {pt[:70]}")

    # ── F: YAR as key/primer ────────────────────────────────────────────
    print()
    print("=" * 70)
    print("TEST F: YAR as key/primer (the removed superscript letters)")
    print("  YAR = superscript at K3/K4 boundary, removed to create grille")
    print("  RAY (reversed) = 'ray of light' (hold to light instruction)")
    print("  ILM = tableau letters UNDER YAR when folded")
    print("=" * 70)

    yar_keys = {
        "YAR": "YAR",
        "RAY": "RAY",           # reversed = ray of light
        "ILM": "ILM",           # what's under YAR when folded
        "YARILM": "YARILM",     # combined
        "ILMYAR": "ILMYAR",     # reversed combination
        "RAYILM": "RAYILM",     # ray + ILM
        "YARKRYPTOS": "YARKRYPTOS",   # YAR + known keyword
        "RAYKRYPTOS": "RAYKRYPTOS",
        "ILMKRYPTOS": "ILMKRYPTOS",
    }

    for key_name, key in yar_keys.items():
        print(f"\n  Key: {key_name} = '{key}'")
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            if not all(c in alpha for c in key):
                print(f"    {alpha_name}: key has invalid chars, skipping")
                continue
            for cipher_name, cipher_fn in [
                ("vig", vig_decrypt), ("beau", beau_decrypt),
                ("autokey_pt", autokey_pt_decrypt), ("autokey_ct", autokey_ct_decrypt),
            ]:
                pt = cipher_fn(GRILLE_CT, key, alpha)
                sc = score_text(pt)
                cribs = has_cribs(pt)
                marker = " ***" if sc > -700 or cribs else ""
                crib_str = f" CRIBS={cribs}" if cribs else ""
                print(f"    {cipher_name}/{alpha_name}: score={sc:>8.1f}{crib_str}{marker}")
                if sc > -800 or cribs:
                    print(f"      PT: {pt[:70]}")

    # ── G: YAR KA-indices as Gronsfeld key ────────────────────────────
    print()
    print("=" * 70)
    print("TEST G: YAR as numeric key (KA indices: Y=2, A=7, R=1)")
    print("=" * 70)

    yar_ka = [KA.index(c) for c in "YAR"]  # [2, 7, 1]
    yar_az = [AZ.index(c) for c in "YAR"]  # [24, 0, 17]
    ilm_ka = [KA.index(c) for c in "ILM"]
    ilm_az = [AZ.index(c) for c in "ILM"]

    for name, shifts in [("YAR_KA", yar_ka), ("YAR_AZ", yar_az),
                         ("ILM_KA", ilm_ka), ("ILM_AZ", ilm_az)]:
        print(f"\n  Key: {name} = {shifts}")
        for alpha_name, alpha in [("KA", KA), ("AZ", AZ)]:
            pt = "".join(alpha[(alpha.index(c) - shifts[i % len(shifts)]) % 26]
                         for i, c in enumerate(GRILLE_CT))
            sc = score_text(pt)
            cribs = has_cribs(pt)
            marker = " ***" if sc > -700 or cribs else ""
            crib_str = f" CRIBS={cribs}" if cribs else ""
            print(f"    gronsfeld/{alpha_name}: score={sc:>8.1f}{crib_str}{marker}")
            if sc > -800 or cribs:
                print(f"      PT: {pt[:70]}")

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Cipher-side key through holes: {cipher_key_clean[:40]}...")
    print(f"  Plaintext key through holes:   {known_pt[:40]}...")
    print(f"  Row labels key:                {unique_row_key}")
    print(f"  Column-index keys:             AZ={col_key_az} KA={col_key_ka}")
    print(f"  Hole-count Gronsfeld:          {hole_counts}")
    print()


if __name__ == "__main__":
    main()
