#!/usr/bin/env python3
"""E-S-15: Creative key generation hypotheses.

Tests non-standard key generation methods inspired by Sanborn's 2025 clues:
1. Date-derived keys (1986 Egypt trip, 1989 Berlin Wall)
2. Coordinate-derived keys (38°57'6.5"N, 77°8'44"W)
3. Known keyword expansion rules (Gronsfeld, digit-to-letter maps)
4. K1-K3 ciphertext/plaintext as running key at ALL offsets
5. Sculpture text features (letter frequencies, positions)
6. Clock-derived sequences (Urania Weltzeituhr)
7. Alphabetic-position key from thematic words
8. Combined: keyword + date offset

For each key hypothesis, checks Vigenère and Beaufort decryption
against cribs AND quadgram fitness of full plaintext.
"""

import json
import math
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_ENTRIES, MOD

# ═══ Setup ════════════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
CRIB_DICT = {p: c for p, c in _sorted}
PT_INT = {p: ord(c) - 65 for p, c in _sorted}
N_CRIBS = len(CRIB_POS)

# Known keystream at crib positions (Vigenère)
VIG_KEY = {}
for p in CRIB_POS:
    VIG_KEY[p] = (CT_INT[p] - PT_INT[p]) % 26

# Known keystream at crib positions (Beaufort)
BEAU_KEY = {}
for p in CRIB_POS:
    BEAU_KEY[p] = (CT_INT[p] + PT_INT[p]) % 26

# Load quadgrams if available
QUADGRAM_SCORES = None
try:
    qg_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
    with open(qg_path) as f:
        qg_data = json.load(f)
    if 'logp' in qg_data:
        QUADGRAM_SCORES = qg_data['logp']
    else:
        QUADGRAM_SCORES = qg_data
    QG_FLOOR = min(QUADGRAM_SCORES.values()) if QUADGRAM_SCORES else -10
    print(f"Quadgram scorer loaded: {len(QUADGRAM_SCORES)} entries, floor={QG_FLOOR:.3f}")
except Exception as e:
    print(f"Quadgrams not available: {e}")
    QG_FLOOR = -10


def quadgram_score(text):
    """Score text by quadgram log-probabilities."""
    if QUADGRAM_SCORES is None:
        return -10 * len(text)
    score = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAM_SCORES.get(qg, QG_FLOOR)
    return score


def score_key(key_seq, variant='vigenere'):
    """Given a full key sequence (length >= CT_LEN), decrypt and score.

    Returns (crib_matches, qg_per_char, plaintext).
    """
    pt = []
    for i in range(CT_LEN):
        k = key_seq[i % len(key_seq)] if i < len(key_seq) else key_seq[i % len(key_seq)]
        if variant == 'vigenere':
            p = (CT_INT[i] - k) % 26
        else:  # beaufort
            p = (k - CT_INT[i]) % 26
        pt.append(chr(p + 65))
    pt_str = ''.join(pt)

    # Count crib matches
    matches = 0
    for p in CRIB_POS:
        if pt[p] == CRIB_DICT[p]:
            matches += 1

    # Quadgram score
    qg = quadgram_score(pt_str) / max(len(pt_str) - 3, 1)

    return matches, qg, pt_str


def check_key_at_cribs(key_seq, variant='vigenere'):
    """Quick check: how many crib positions match?"""
    matches = 0
    for p in CRIB_POS:
        k = key_seq[p] if p < len(key_seq) else key_seq[p % len(key_seq)]
        if variant == 'vigenere':
            expected = VIG_KEY[p]
        else:
            expected = BEAU_KEY[p]
        if k == expected:
            matches += 1
    return matches


# ═══ Key generators ═══════════════════════════════════════════════════════

def gen_date_keys():
    """Generate keys from dates associated with Kryptos."""
    keys = {}

    # Key dates
    dates = {
        "berlin_wall_fall": (1989, 11, 9),
        "berlin_wall_fall_eu": (1989, 9, 11),
        "egypt_1986": (1986, 1, 1),  # month unknown
        "kryptos_dedication": (1990, 11, 3),
        "k123_solved": (1999, 1, 1),
        "cia_founded": (1947, 9, 18),
        "sanborn_born": (1945, 1, 1),  # approximate
    }

    for name, (year, month, day) in dates.items():
        # Digits of date as key values
        digits = [int(d) for d in f"{year:04d}{month:02d}{day:02d}"]
        keys[f"date_{name}_digits"] = digits

        # Year digits only, repeated
        yd = [int(d) for d in str(year)]
        keys[f"date_{name}_year"] = yd

        # Month+day as key
        md = [int(d) for d in f"{month:02d}{day:02d}"]
        keys[f"date_{name}_monthday"] = md

        # Sum patterns
        keys[f"date_{name}_ymd"] = [year % 26, month % 26, day % 26]

        # Gronsfeld-style (digits 0-9 as shifts)
        keys[f"date_{name}_gronsfeld"] = digits

    # Julian dates and differences
    # Berlin Wall fall: Julian day 2447837
    # Days between events
    keys["days_86_89"] = [int(d) for d in str(1096)]  # ~3 years
    keys["days_86_89_mod26"] = [1096 % 26]  # = 4

    # Year pairs
    keys["years_1986_1989"] = [1, 9, 8, 6, 1, 9, 8, 9]
    keys["years_diff"] = [3]  # 1989 - 1986

    return keys


def gen_coordinate_keys():
    """Generate keys from Kryptos coordinates."""
    keys = {}

    # 38°57'6.5"N, 77°8'44"W
    # As digits
    keys["coord_full"] = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
    keys["coord_north"] = [3, 8, 5, 7, 6, 5]
    keys["coord_west"] = [7, 7, 8, 4, 4]
    keys["coord_interleaved"] = [3, 7, 8, 7, 5, 8, 7, 4, 6, 4, 5]

    # As letter positions (A=1, B=2, ...)
    keys["coord_letters_N"] = [3, 8, 5, 7, 6, 5]  # same as digits for single-digit
    keys["coord_degrees"] = [38 % 26, 57 % 26, 6, 77 % 26, 8, 44 % 26]  # [12, 5, 6, 25, 8, 18]

    # Sexagesimal components
    keys["coord_sexa_N"] = [38, 57, 6]
    keys["coord_sexa_W"] = [77, 8, 44]
    keys["coord_sexa_both"] = [38, 57, 6, 77, 8, 44]
    keys["coord_sexa_mod26"] = [38 % 26, 57 % 26, 6 % 26, 77 % 26, 8 % 26, 44 % 26]

    return keys


def gen_word_position_keys():
    """Generate keys from alphabetic positions of thematic words."""
    keys = {}

    words = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "FORCES",
        "BERLIN", "CLOCK", "EGYPT", "CAIRO", "GIZA",
        "POINT", "MESSAGE", "DELIVER", "CANDLE", "TOMB",
        "CARTER", "SCHEIDT", "SANBORN", "LANGLEY", "CIPHER",
        "EASTNORTHEAST", "BERLINCLOCK",
        "WHATSTHEPOINT", "THEPOINT",
        "IQLUSION", "ILLUSION", "VIRTUALLY", "INVISIBLE",
        "DESPERATLY", "UNDERGRUUND",
        "TUTANKHAMUN", "PHARAOH", "PYRAMIDS",
        "MAGNETIC", "COMPASS", "NORTH", "EAST",
        "NOVEMBER", "NINETEEN", "EIGHTYNINE",
        "COLDWAR", "WALL", "REUNIFICATION",
    ]

    for word in words:
        # Letter positions (A=0, B=1, ...)
        pos = [ord(c) - 65 for c in word]
        keys[f"word_{word}"] = pos

        # Reversed
        keys[f"word_{word}_rev"] = list(reversed(pos))

        # Delta sequence
        if len(pos) > 1:
            deltas = [(pos[i+1] - pos[i]) % 26 for i in range(len(pos) - 1)]
            keys[f"word_{word}_delta"] = deltas

    return keys


def gen_fibonacci_keys():
    """Generate keys from mathematical sequences."""
    keys = {}

    # Fibonacci mod 26
    fib = [0, 1]
    for _ in range(95):
        fib.append((fib[-1] + fib[-2]) % 26)
    keys["fibonacci_mod26"] = fib[:97]

    # Primes mod 26
    def is_prime(n):
        if n < 2: return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0: return False
        return True
    primes = [p % 26 for p in range(2, 600) if is_prime(p)][:97]
    keys["primes_mod26"] = primes

    # Triangular numbers mod 26
    tri = [((n * (n + 1)) // 2) % 26 for n in range(97)]
    keys["triangular_mod26"] = tri

    # Powers of 2 mod 26
    pow2 = [(2 ** n) % 26 for n in range(97)]
    keys["pow2_mod26"] = pow2

    # Square roots (integer part) mod 26
    sqr = [int(math.sqrt(n)) % 26 for n in range(97)]
    keys["sqrt_mod26"] = sqr

    # Pi digits mod 26
    pi_digits = [3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,3,8,4,6,2,6,4,3,3,8,3,2,7,9,5,0,2,8,8,4,1,9,7,1,6,9,3,9,9,3,7,5,1,0,5,8,2,0,9,7,4,9,4,4,5,9,2,3,0,7,8,1,6,4,0,6,2,8,6,2,0,8,9,9,8,6,2,8,0,3,4,8,2,5,3,4,2,1,1,7]
    keys["pi_digits"] = pi_digits[:97]
    keys["pi_digits_mod26"] = [d % 26 for d in pi_digits[:97]]

    # e digits
    e_digits = [2,7,1,8,2,8,1,8,2,8,4,5,9,0,4,5,2,3,5,3,6,0,2,8,7,4,7,1,3,5,2,6,6,2,4,9,7,7,5,7,2,4,7,0,9,3,6,9,9,9,5,9,5,7,4,9,6,6,9,6,7,6,2,7,7,2,4,0,7,6,6,3,0,3,5,3,5,4,7,5,9,4,5,7,1,3,8,2,1,7,8,5,2,5,1,6,6]
    keys["e_digits"] = e_digits[:97]

    return keys


def gen_sculpture_derived_keys():
    """Keys derived from the sculpture text itself."""
    keys = {}

    # K4 CT letter positions as key (self-referential)
    keys["ct_self"] = CT_INT

    # CT reversed
    keys["ct_reversed"] = list(reversed(CT_INT))

    # CT shifted by various amounts
    for shift in range(1, 26):
        keys[f"ct_shift_{shift}"] = [(c + shift) % 26 for c in CT_INT]

    # CT cumulative sum mod 26
    cum = [0] * CT_LEN
    cum[0] = CT_INT[0]
    for i in range(1, CT_LEN):
        cum[i] = (cum[i-1] + CT_INT[i]) % 26
    keys["ct_cumsum"] = cum

    # CT difference sequence
    diff = [(CT_INT[i+1] - CT_INT[i]) % 26 for i in range(CT_LEN - 1)]
    keys["ct_diff"] = diff + [0]

    # K1/K2/K3 ciphertexts
    K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    K2_CT = "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK?DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFM"
    K3_CT = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW"

    keys["K1_CT"] = [ord(c) - 65 for c in K1_CT if c.isalpha()]
    keys["K2_CT"] = [ord(c) - 65 for c in K2_CT if c.isalpha()]
    keys["K3_CT"] = [ord(c) - 65 for c in K3_CT if c.isalpha()]

    # K1-K3 plaintexts
    K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETIC"
             "FIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOAN"
             "UNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHIS"
             "THEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
             "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
             "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
             "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO")
    K3_PT = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
             "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSI"
             "MADEATINYBREACHINTHEUPPER"
             "LEFTHANDCORNERANDTHENWIDENINTHEHOLEALITTLEIINSERTEDTHECANDLE"
             "ANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
             "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOM"
             "WITHINEMERGEFROMTHEMISTXCANYOUSEEANYTHINGQ")

    keys["K1_PT"] = [ord(c) - 65 for c in K1_PT]
    keys["K2_PT"] = [ord(c) - 65 for c in K2_PT]
    keys["K3_PT"] = [ord(c) - 65 for c in K3_PT]

    # Concatenated
    all_pt = K1_PT + K2_PT + K3_PT
    keys["K123_PT"] = [ord(c) - 65 for c in all_pt]

    all_ct = K1_CT + K2_CT + K3_CT
    keys["K123_CT"] = [ord(c) - 65 for c in all_ct if c.isalpha()]

    return keys


def gen_combined_keys():
    """Keys combining keyword base + date/coordinate offset."""
    keys = {}

    base_words = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN",
                  "CLOCK", "SHADOW", "POINT", "LANGLEY"]
    offsets = [
        ("1989", [1,9,8,9]),
        ("1986", [1,9,8,6]),
        ("date_bw", [1,9,8,9,1,1,0,9]),
        ("coord", [3,8,5,7,6,5,7,7,8,4,4]),
    ]

    for word in base_words:
        word_vals = [ord(c) - 65 for c in word]
        for off_name, off_vals in offsets:
            # Add offset to keyword (repeating keyword)
            combined = []
            for i in range(97):
                w = word_vals[i % len(word_vals)]
                o = off_vals[i % len(off_vals)]
                combined.append((w + o) % 26)
            keys[f"combo_{word}_{off_name}_add"] = combined

            # XOR-like (multiply)
            combined_m = []
            for i in range(97):
                w = word_vals[i % len(word_vals)]
                o = off_vals[i % len(off_vals)]
                combined_m.append((w * o) % 26)
            keys[f"combo_{word}_{off_name}_mul"] = combined_m

    return keys


# ═══ Main ═════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-15: Creative Key Generation Hypotheses")
    print("=" * 60)
    print()

    # Generate all key hypotheses
    all_keys = {}
    generators = [
        ("dates", gen_date_keys),
        ("coordinates", gen_coordinate_keys),
        ("word_positions", gen_word_position_keys),
        ("fibonacci/math", gen_fibonacci_keys),
        ("sculpture", gen_sculpture_derived_keys),
        ("combined", gen_combined_keys),
    ]

    for gen_name, gen_func in generators:
        ks = gen_func()
        print(f"  {gen_name}: {len(ks)} key hypotheses")
        all_keys.update(ks)

    print(f"\nTotal key hypotheses: {len(all_keys)}")
    print()

    # Test each key
    all_results = []
    global_best = {"matches": 0}

    for key_name, key_seq in all_keys.items():
        if not key_seq or len(key_seq) == 0:
            continue

        # Ensure key_seq values are in [0, 25]
        key_seq = [k % 26 for k in key_seq]

        for variant in ['vigenere', 'beaufort']:
            matches = check_key_at_cribs(key_seq, variant)

            entry = {
                "key_name": key_name,
                "variant": variant,
                "key_len": len(key_seq),
                "matches": matches,
            }

            if matches >= 5:  # Only compute expensive quadgrams for promising keys
                _, qg, pt = score_key(key_seq, variant)
                entry["qg_per_char"] = round(qg, 3)
                entry["pt_preview"] = pt[:50]

            all_results.append(entry)

            if matches > global_best["matches"]:
                _, qg, pt = score_key(key_seq, variant)
                global_best = {
                    "matches": matches,
                    "key_name": key_name,
                    "variant": variant,
                    "key_len": len(key_seq),
                    "qg_per_char": round(qg, 3),
                    "pt_preview": pt[:50],
                    "key_preview": key_seq[:20],
                }

    # Also test running key offsets for longer texts
    print("Testing running key offsets for longer texts...")
    long_keys = {k: v for k, v in all_keys.items()
                 if len(v) >= CT_LEN + 50}

    for key_name, key_seq in long_keys.items():
        key_seq = [k % 26 for k in key_seq]
        max_offset = len(key_seq) - CT_LEN

        for variant in ['vigenere', 'beaufort']:
            best_offset_matches = 0
            best_offset = 0

            for offset in range(max_offset + 1):
                sub_key = key_seq[offset:offset + CT_LEN]
                matches = check_key_at_cribs(sub_key, variant)
                if matches > best_offset_matches:
                    best_offset_matches = matches
                    best_offset = offset

            if best_offset_matches > 3:
                entry = {
                    "key_name": f"{key_name}@{best_offset}",
                    "variant": variant,
                    "key_len": CT_LEN,
                    "matches": best_offset_matches,
                    "offset": best_offset,
                }
                if best_offset_matches >= 5:
                    sub_key = key_seq[best_offset:best_offset + CT_LEN]
                    _, qg, pt = score_key(sub_key, variant)
                    entry["qg_per_char"] = round(qg, 3)
                    entry["pt_preview"] = pt[:50]
                all_results.append(entry)

                if best_offset_matches > global_best["matches"]:
                    sub_key = key_seq[best_offset:best_offset + CT_LEN]
                    _, qg, pt = score_key(sub_key, variant)
                    global_best = {
                        "matches": best_offset_matches,
                        "key_name": f"{key_name}@{best_offset}",
                        "variant": variant,
                        "key_len": CT_LEN,
                        "qg_per_char": round(qg, 3),
                        "pt_preview": pt[:50],
                        "offset": best_offset,
                    }

    # ═══ Summary ═══════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    all_results.sort(key=lambda x: -x["matches"])

    print(f"\n{'=' * 60}")
    print(f"  TOP 20 KEY HYPOTHESES")
    print(f"{'=' * 60}")
    for i, r in enumerate(all_results[:20]):
        extra = ""
        if "qg_per_char" in r:
            extra = f"  qg={r['qg_per_char']:.2f}"
        if "pt_preview" in r:
            extra += f"  PT={r['pt_preview'][:30]}..."
        print(f"  {i+1:>2}. {r['key_name']:<35s} {r['variant']:<8s} "
              f"matches={r['matches']}/24{extra}")

    # Score distribution
    match_counts = Counter(r["matches"] for r in all_results)
    print(f"\n  Match distribution: {dict(sorted(match_counts.items(), reverse=True))}")

    # Expected: for a random key of length L ≤ 97, each position has 1/26 chance
    # of matching the required key value. Expected matches = 24/26 ≈ 0.92
    # For repeating key of length L, some positions share the same key letter,
    # so expected matches depend on the period structure.
    print(f"\n  Expected random matches: ~{24/26:.1f}/24 (short key) to ~{24*1/26:.1f}/24 (long key)")

    if global_best["matches"] >= 10:
        verdict = "SIGNAL"
    elif global_best["matches"] >= 5:
        verdict = "INVESTIGATE"
    else:
        verdict = "NOISE"

    print(f"\n  Global best: {global_best['matches']}/24 ({global_best.get('key_name', '?')})")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_15_creative_keys.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-15",
            "hypothesis": "Key derived from dates, coordinates, words, or sculpture features",
            "total_time_s": round(elapsed, 1),
            "verdict": verdict,
            "n_keys_tested": len(all_results),
            "global_best": global_best,
            "top_20": all_results[:20],
            "match_distribution": dict(sorted(match_counts.items(), reverse=True)),
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_15_creative_keys.py")
    print(f"\nRESULT: best={global_best['matches']}/24 verdict={verdict}")


if __name__ == "__main__":
    main()
