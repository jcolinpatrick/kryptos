#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-24: Thematic Key Derivation

Sanborn's 2025 clues point to specific events:
- 1986 Egypt trip (Tutankhamun, Carter, Valley of the Kings)
- 1989 Berlin Wall fall (November 9, 1989)
- "Delivering a message"
- "What's the point?" (deliberate clue)
- BERLINCLOCK = Urania Weltzeituhr (Alexanderplatz clock)

This experiment derives keys from these themes and tests them
as Vigenère/Beaufort keys at multiple periods, combined with
various transposition structures.

Key sources:
1. Dates: 1986, 1989, 11091989, 19860101, etc.
2. Place names: CAIRO, GIZA, LUXOR, BERLIN, ALEXANDERPLATZ, etc.
3. People: CARTER, SANBORN, SCHEIDT, TUTANKHAMUN, etc.
4. Phrases: WHATSTHEPOINT, DELIVERINGAMESSAGE, etc.
5. Coordinates: CIA HQ (38.9517, -77.1467), Kryptos coords, etc.
6. Combined: KRYPTOS+date, keyword+offset, etc.

For each candidate key:
- Test as periodic Vigenère/Beaufort key
- Test as running key (repeated to 97 chars)
- Test with identity transposition AND with simple transpositions

Output: results/e_s_24_thematic_keys.json
"""
import json
import sys
import time
from collections import defaultdict

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN

# ── Key generation from themes ──────────────────────────────────────────

def text_to_nums(text):
    """Convert alphabetic text to numeric values (A=0, B=1, ...)."""
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]

def date_to_nums(date_str):
    """Convert date digits to key values. E.g., '1989' -> [1,9,8,9]."""
    return [int(c) for c in date_str if c.isdigit()]

def coords_to_key(lat, lon, precision=6):
    """Convert coordinates to key by extracting digits."""
    lat_str = f"{abs(lat):.{precision}f}".replace(".", "")
    lon_str = f"{abs(lon):.{precision}f}".replace(".", "")
    combined = lat_str + lon_str
    return [int(c) for c in combined]


# Generate all candidate keys
CANDIDATE_KEYS = []

# 1. Thematic words and phrases
words = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "FORCES",
    "EASTNORTHEAST", "BERLINCLOCK",
    "BERLIN", "CAIRO", "GIZA", "LUXOR", "EGYPT", "THEBES",
    "CARTER", "TUTANKHAMUN", "HOWARD", "HOWARDCARTER",
    "SANBORN", "SCHEIDT", "WEBSTER", "LANGLEY",
    "ALEXANDERPLATZ", "URANIA", "WELTZEITUHR",
    "BERLINWALL", "NOVEMBER", "NINETEEN", "EIGHTYNINE",
    "VALLEYOFTHEKINGS", "TOMBOFTUTANKHAMUN",
    "WHATSTHEPOINT", "DELIVERINGAMESSAGE", "MESSAGE",
    "DELIVERING", "BURIED", "COMPASS", "NORTHEAST",
    "PALIMPSESTABSCISSA", "KRYPTOSPALIMPSEST",
    "SECRETMESSAGE", "HIDDENMESSAGE",
    "IQLUSION", "VIRTUALLYINVISIBLE",
    "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION",
    "SLOWLYDESPARATLYSLOWLY",
    "LAYERTWO", "KEYTWO", "STEPTWO",
    "DIGETAL", "INTERPRETATU",
    "POINT", "THEPOINT", "POINTOFNORETURN",
]

for word in words:
    nums = text_to_nums(word)
    if nums:
        CANDIDATE_KEYS.append((f"word:{word}", nums))

# 2. Dates
dates = [
    ("date:1986", "1986"),
    ("date:1989", "1989"),
    ("date:19860101", "19860101"),
    ("date:19891109", "19891109"),
    ("date:11091989", "11091989"),
    ("date:01011986", "01011986"),
    ("date:1109", "1109"),
    ("date:0101", "0101"),
    ("date:19861989", "19861989"),
    ("date:19891986", "19891986"),
    ("date:1990", "1990"),  # Year Kryptos installed
    ("date:19901103", "19901103"),  # Kryptos dedication date
    ("date:03111990", "03111990"),
    ("date:86", "86"),
    ("date:89", "89"),
    ("date:8689", "8689"),
]

for name, date_str in dates:
    nums = date_to_nums(date_str)
    if nums:
        CANDIDATE_KEYS.append((name, nums))

# 3. Coordinates
coords = [
    ("coords:CIA_HQ", 38.9517, -77.1467),
    ("coords:Kryptos_sculpture", 38.9518, -77.1461),
    ("coords:Berlin_Wall", 52.5163, 13.3777),
    ("coords:Alexanderplatz", 52.5219, 13.4132),
    ("coords:Valley_Kings", 25.7402, 32.6014),
    ("coords:Giza_pyramids", 29.9792, 31.1342),
    ("coords:Cairo_museum", 30.0478, 31.2336),
    ("coords:Tomb_Tut", 25.7406, 32.6013),
]

for name, lat, lon in coords:
    for prec in [2, 4, 6]:
        nums = coords_to_key(lat, lon, prec)
        CANDIDATE_KEYS.append((f"{name}_p{prec}", nums))

# 4. Combined keys (word + date interleaved)
for word in ["KRYPTOS", "PALIMPSEST", "BERLIN", "CAIRO", "CARTER"]:
    for date_str in ["1986", "1989", "19891109"]:
        word_nums = text_to_nums(word)
        date_nums = date_to_nums(date_str)
        # Interleave
        combined = []
        for i in range(max(len(word_nums), len(date_nums))):
            if i < len(word_nums):
                combined.append(word_nums[i])
            if i < len(date_nums):
                combined.append(date_nums[i])
        CANDIDATE_KEYS.append((f"interleave:{word}+{date_str}", combined))
        # Concatenate
        CANDIDATE_KEYS.append((f"concat:{word}+{date_str}", word_nums + date_nums))
        # XOR mod 26
        xor_nums = [(word_nums[i % len(word_nums)] + date_nums[i % len(date_nums)]) % MOD
                     for i in range(max(len(word_nums), len(date_nums)))]
        CANDIDATE_KEYS.append((f"add:{word}+{date_str}", xor_nums))

# 5. Numeric encodings of words
for word in ["KRYPTOS", "BERLIN", "CAIRO", "CARTER", "POINT"]:
    nums = text_to_nums(word)
    # Reverse
    CANDIDATE_KEYS.append((f"rev:{word}", list(reversed(nums))))
    # Complement (25-x)
    CANDIDATE_KEYS.append((f"comp:{word}", [(25 - x) % MOD for x in nums]))
    # Squared mod 26
    CANDIDATE_KEYS.append((f"sq:{word}", [(x * x) % MOD for x in nums]))

print(f"Generated {len(CANDIDATE_KEYS)} candidate keys")


# ── Scoring ──────────────────────────────────────────────────────────────

def score_periodic_key(key_nums, period, variant="vig"):
    """Score a periodic key against cribs (identity transposition).

    Key is used cyclically: key[j] = key_nums[j % period]
    """
    matches = 0
    for pt_pos in CRIB_POS:
        ct_val = CT_NUM[pt_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        k = key_nums[pt_pos % period] if pt_pos % period < len(key_nums) else 0

        if variant == "vig":
            expected_ct = (pt_val + k) % MOD
        else:  # beaufort
            expected_ct = (k - pt_val) % MOD

        if expected_ct == ct_val:
            matches += 1

    return matches


def score_running_key(key_nums, variant="vig"):
    """Score a running key (key repeated to cover full CT length)."""
    if not key_nums:
        return 0

    matches = 0
    for pt_pos in CRIB_POS:
        ct_val = CT_NUM[pt_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        k = key_nums[pt_pos % len(key_nums)]

        if variant == "vig":
            expected_ct = (pt_val + k) % MOD
        else:
            expected_ct = (k - pt_val) % MOD

        if expected_ct == ct_val:
            matches += 1

    return matches


def check_bean_for_key(key_nums, period):
    """Check Bean constraints for a periodic key."""
    if not key_nums or period > len(key_nums):
        return None  # Can't check

    bean_pass = True
    for pos_a, pos_b in BEAN_EQ:
        ka = key_nums[pos_a % period] if pos_a % period < len(key_nums) else -1
        kb = key_nums[pos_b % period] if pos_b % period < len(key_nums) else -1
        if ka >= 0 and kb >= 0 and ka != kb:
            bean_pass = False
            break

    if bean_pass:
        for pos_a, pos_b in BEAN_INEQ:
            ka = key_nums[pos_a % period] if pos_a % period < len(key_nums) else -1
            kb = key_nums[pos_b % period] if pos_b % period < len(key_nums) else -1
            if ka >= 0 and kb >= 0 and ka == kb:
                bean_pass = False
                break

    return bean_pass


# ── Main sweep ───────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("E-S-24: Thematic Key Derivation")
    print("=" * 60)
    print(f"Testing {len(CANDIDATE_KEYS)} candidate keys")
    print(f"Periods: key length, and 3-13")
    print(f"Variants: Vigenère, Beaufort")
    print()

    t0 = time.time()
    top_results = []
    total_configs = 0

    for key_name, key_nums in CANDIDATE_KEYS:
        key_len = len(key_nums)

        # Test as periodic key at its natural length and other periods
        periods_to_test = sorted(set([key_len] + list(range(3, 14))))

        for period in periods_to_test:
            if period > key_len:
                # Pad key with zeros (or skip)
                continue

            for variant in ["vig", "beau"]:
                score = score_periodic_key(key_nums, period, variant)
                bean = check_bean_for_key(key_nums, period)
                total_configs += 1

                if score >= 8:
                    top_results.append({
                        "score": score,
                        "bean": bean,
                        "key_name": key_name,
                        "key_nums": key_nums[:period],
                        "key_letters": "".join(ALPH[k % MOD] for k in key_nums[:period]),
                        "period": period,
                        "variant": variant,
                        "mode": "periodic",
                    })

        # Test as running key (full length, not periodic)
        for variant in ["vig", "beau"]:
            score = score_running_key(key_nums, variant)
            total_configs += 1

            if score >= 8:
                top_results.append({
                    "score": score,
                    "bean": None,
                    "key_name": key_name,
                    "key_nums": key_nums[:20],  # First 20 for brevity
                    "key_letters": "".join(ALPH[k % MOD] for k in key_nums[:20]),
                    "period": key_len,
                    "variant": variant,
                    "mode": "running",
                })

    elapsed = time.time() - t0

    # Also test shifts/offsets of each key
    print(f"\nPhase 2: Testing shifted keys...")
    for key_name, key_nums in CANDIDATE_KEYS:
        key_len = len(key_nums)
        if key_len > 20:
            continue  # Skip long keys for shift testing

        for shift in range(1, MOD):
            shifted = [(k + shift) % MOD for k in key_nums]
            for period in [key_len, 7, 5, 6]:
                if period > key_len:
                    continue
                for variant in ["vig", "beau"]:
                    score = score_periodic_key(shifted, period, variant)
                    total_configs += 1
                    if score >= 10:
                        top_results.append({
                            "score": score,
                            "bean": check_bean_for_key(shifted, period),
                            "key_name": f"shift({key_name},+{shift})",
                            "key_nums": shifted[:period],
                            "key_letters": "".join(ALPH[k % MOD] for k in shifted[:period]),
                            "period": period,
                            "variant": variant,
                            "mode": "shifted_periodic",
                        })

    elapsed = time.time() - t0

    # Sort
    top_results.sort(key=lambda x: (-x["score"], -int(x["bean"] or 0)))

    # Summary
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Total configs: {total_configs:,}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Noise floor (p=7): ~8.2/24")
    print()

    # Score distribution
    score_dist = defaultdict(int)
    for r in top_results:
        score_dist[r["score"]] += 1
    print(f"  Score distribution (≥8/24):")
    for s in sorted(score_dist, reverse=True):
        print(f"    {s}/24: {score_dist[s]} configs")

    # Top 30
    print(f"\n  Top 30 results:")
    for i, r in enumerate(top_results[:30]):
        print(f"    {i+1:>2}. {r['score']}/24  bean={str(r['bean'])[:1]:>1}"
              f"  {r['key_name']:<35}  {r['variant']}"
              f"  p={r['period']}  key={r['key_letters']}"
              f"  ({r['mode']})")

    # Global best
    global_best = top_results[0]["score"] if top_results else 0

    # Verdict
    if global_best >= 18:
        verdict = "SIGNAL"
    elif global_best >= 10:
        verdict = "INVESTIGATE"
    else:
        verdict = "NOISE"

    print(f"\n  Global best: {global_best}/24")
    print(f"  Verdict: {verdict}")

    # Save
    output = {
        "experiment": "E-S-24",
        "description": "Thematic key derivation from 2025 clues",
        "total_configs": total_configs,
        "elapsed_seconds": elapsed,
        "n_candidate_keys": len(CANDIDATE_KEYS),
        "global_best_score": global_best,
        "verdict": verdict,
        "top_results": top_results[:100],
    }

    with open("results/e_s_24_thematic_keys.json", "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n  Artifact: results/e_s_24_thematic_keys.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_24_thematic_keys.py")


if __name__ == "__main__":
    main()
