#!/usr/bin/env python3
"""
E-S-43: Thematic Plaintext Extension and Key Analysis

Given the underdetermination wall (E-S-40), we pivot to a plaintext-first
approach. Instead of cracking the cipher method, we try to guess MORE
plaintext characters from thematic clues, then check if the extended
plaintext reveals key structure.

APPROACH:
For each candidate word/phrase (from K4's known themes):
1. Place it at every valid position (not conflicting with existing cribs)
2. Under identity transposition + Vigenère, compute the derived keystream
3. Score by: key entropy, repeats, English fragments, period patterns

THEMES (from Sanborn's clues):
- 1986 Egypt trip: TOMB, CARTER, TUTANKHAMUN, VALLEY, KINGS, EGYPT, CAIRO
- 1989 Berlin Wall fall: WALL, FALL, NOVEMBER, NINETEEN, EIGHTYNINE, REAGAN
- "Delivering a message": MESSAGE, DELIVER, TRANSMIT, COURIER, AGENT
- "What's the point?": POINT, THEPOINT, WHATISTHEPOINT, COMPASS, BEARING
- Kryptos vocabulary: KRYPTOS, PALIMPSEST, ABSCISSA, SHADOW, BETWEEN
- Intelligence/CIA: SECRET, CLASSIFIED, BURIED, HIDDEN, COORDINATES
- K1-K3 themes: IQLUSION, VIRTUALLY, INVISIBLE, DESPARATLY, SLOWLY

Output: results/e_s_43_thematic_extension.json
"""

import json
import sys
import os
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())

# Known Vigenère keystream at crib positions
KNOWN_KEY = {}
for pos, pt_ch in CRIB_DICT.items():
    KNOWN_KEY[pos] = (CT_NUM[pos] - ALPH_IDX[pt_ch]) % MOD


def load_wordlist():
    """Load English dictionary for key fragment matching."""
    path = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'english.txt')
    if os.path.exists(path):
        with open(path) as f:
            return set(w.strip().upper() for w in f if len(w.strip()) >= 3)
    return set()


THEMATIC_WORDS = [
    # 1986 Egypt / Carter / Tutankhamun
    "TOMB", "CARTER", "HOWARD", "TUTANKHAMUN", "VALLEY", "KINGS",
    "EGYPT", "CAIRO", "LUXOR", "PHARAOH", "EXCAVATION", "DISCOVERY",
    "CHAMBER", "BURIAL", "SARCOPHAGUS", "TREASURE", "THEBES",
    "NILE", "PYRAMID", "SPHINX", "ANKH", "HIEROGLYPH",
    "WONDERFUL", "THINGS", "WONDERFULTHINGS",
    "CANISEETHEM", "YESYES",
    "THEVALLEYOFTHEKINGS", "TOMBOFTUTANKHAMUN",
    "THETOMBOFTUT", "KINGSVALLEY",

    # 1989 Berlin Wall
    "WALL", "FALL", "BERLINWALL", "THEWALL", "CHECKPOINT",
    "CHARLIE", "NOVEMBER", "NINETEEN", "EIGHTYNINE", "REAGAN",
    "GORBACHEV", "TEARDOWNTHISWALL", "FREEDOMBELL",
    "BRANDENBURGGATE", "BRANDENBURG", "EASTBERLIN", "WESTBERLIN",
    "REUNIFICATION", "COLDWAR", "IRON", "CURTAIN", "IRONCURTAIN",
    "NINETYEIGHTNINE", "NOVEMBER9",

    # "Delivering a message"
    "MESSAGE", "DELIVER", "DELIVERTHEMESSAGE", "TRANSMIT",
    "COURIER", "AGENT", "DISPATCH", "INTELLIGENCE", "REPORT",
    "MISSION", "OPERATION", "OPERATIVE", "COMMUNICATE",
    "ENCRYPT", "DECRYPT", "ENCODE", "DECODE", "CIPHER",
    "THISMESSAGECONTAINS", "THEFOLLOWING",

    # "What's the point?"
    "POINT", "THEPOINT", "WHATISTHEPOINT", "WHATSTHEPOINT",
    "COMPASS", "BEARING", "DIRECTION", "COORDINATE", "COORDINATES",
    "LATITUDE", "LONGITUDE", "DEGREES", "NORTH", "SOUTH", "EAST", "WEST",
    "MAGNETIC", "LODESTONE", "TRUEPOINT",

    # Kryptos vocabulary
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BETWEEN",
    "SUBTLESHADING", "SHADOWFORCES", "LUCID", "MEMORY",
    "VIRTUALLY", "INVISIBLE", "IQLUSION", "DESPARATLY", "SLOWLY",
    "UNDERGRUUND", "PASSAGE", "DEBRIS",

    # Intelligence / CIA
    "SECRET", "CLASSIFIED", "TOPSECRET", "BURIED", "HIDDEN",
    "CONCEALED", "AGENCY", "LANGLEY", "HEADQUARTERS",
    "CLANDESTINE", "COVERT",

    # Numbers as words
    "THIRTYSIX", "THIRTYSEVEN", "THIRTYNINE", "NINETY",
    "SIXTYSEVEN", "TWOTHOUSAND", "NINETEENEIGHTYSIX",
    "NINETEENEIGHTYNINE",

    # K2 related (coordinates, can you see anything)
    "CANYOUSEEANYTHING",
    "ITWASTATOTALLYINVISIBLE",
    "THIRTYEIGHTDEGREES",
    "FIFTYSEVENMINUTES",

    # Short high-value words
    "THE", "AND", "WAS", "FOR", "ARE", "BUT", "NOT", "YOU",
    "ALL", "HER", "HIS", "ONE", "OUR", "OUT", "DAY", "HAD",
    "FROM", "WITH", "THAT", "THIS", "THEY", "HAVE", "BEEN",
    "INTO", "WILL", "WHAT", "WHEN", "WERE", "THERE", "WHERE",
    "WHICH", "COULD", "WOULD", "ABOUT",

    # Specific phrases that might follow known cribs
    # After EASTNORTHEAST (pos 34+):
    "BYSOUTH", "BYEAST", "BYWEST", "BYNORTH",
    "OFTHECOMPASS", "TOWARD", "HEADING",
    # Before EASTNORTHEAST (pos 0-20):
    "DEGREESEASTNORTHEAST",

    # After BERLINCLOCK (pos 74+):
    "TOWER", "STRUCK", "TWELVE", "MIDNIGHT",
    "WASTHEKEY", "ISTHEKEY",
    "POINTED", "TOTHE", "ATTHE",

    # "What's the point" as PT
    "WHATSTHEPOINTWHAT",  # might wrap around

    # Physical features of sculpture
    "PETRIFIED", "WOOD", "COPPER", "QUARTZ", "MORSE",
    "COPPERPLATE", "CURVED", "SURFACE",
]


def place_word(word, start_pos):
    """Try placing word at start_pos. Returns None if conflicts with cribs,
    or dict mapping position → (pt_char, key_value) for non-crib positions."""
    if start_pos < 0 or start_pos + len(word) > N:
        return None

    new_keys = {}
    for i, ch in enumerate(word):
        pos = start_pos + i
        if pos in CRIB_DICT:
            if CRIB_DICT[pos] != ch:
                return None  # Conflict with existing crib
            # else: consistent, skip (already known)
        else:
            key_val = (CT_NUM[pos] - ALPH_IDX[ch]) % MOD
            new_keys[pos] = (ch, key_val)

    return new_keys


def score_key_pattern(combined_keys):
    """Score the combined keystream for patterns.

    Returns dict of scores:
    - entropy: Shannon entropy of key values (lower = more structured)
    - n_repeats: count of key value repetitions
    - max_run: longest run of equal consecutive key values
    - n_zeros: count of key=0 (self-encrypting) positions
    - period_scores: for periods 2-14, count of consistent residues
    - english_fragments: count of 3+ letter English words in key-as-text
    """
    positions = sorted(combined_keys.keys())
    key_vals = [combined_keys[p] for p in positions]

    # Entropy
    counts = Counter(key_vals)
    n = len(key_vals)
    entropy = 0
    for c in counts.values():
        p = c / n
        if p > 0:
            import math
            entropy -= p * math.log2(p)

    # Repeats
    n_repeats = sum(1 for c in counts.values() if c > 1)

    # Zeros
    n_zeros = counts.get(0, 0)

    # Max run of equal consecutive values (by position)
    max_run = 1
    if len(positions) > 1:
        run = 1
        for i in range(1, len(positions)):
            if positions[i] == positions[i-1] + 1 and key_vals[i] == key_vals[i-1]:
                run += 1
                max_run = max(max_run, run)
            else:
                run = 1

    # Period consistency
    period_scores = {}
    for period in range(2, 15):
        residue_groups = defaultdict(list)
        for pos in positions:
            residue_groups[pos % period].append(combined_keys[pos])
        n_consistent = 0
        n_constrained = 0
        for r, vals in residue_groups.items():
            if len(vals) >= 2:
                n_constrained += 1
                if len(set(vals)) == 1:
                    n_consistent += 1
        period_scores[period] = (n_consistent, n_constrained)

    # Key as text (mod 26 → A-Z)
    key_text = ''.join(chr(65 + v) for v in key_vals)

    return {
        'entropy': round(entropy, 3),
        'n_repeats': n_repeats,
        'n_zeros': n_zeros,
        'max_run': max_run,
        'period_scores': period_scores,
        'key_text': key_text,
        'n_positions': n,
    }


def main():
    print("=" * 60)
    print("E-S-43: Thematic Plaintext Extension and Key Analysis")
    print("=" * 60)

    t0 = time.time()
    english_words = load_wordlist()
    print(f"  Loaded {len(english_words)} English words")

    # Remove duplicates and filter
    words = sorted(set(w.upper() for w in THEMATIC_WORDS if w.isalpha() and len(w) >= 3))
    print(f"  Testing {len(words)} thematic words")

    # Build known keystream
    combined_base = dict(KNOWN_KEY)

    all_results = []
    best_entropy = []
    best_period = []
    best_zeros = []

    for word in words:
        for start in range(N - len(word) + 1):
            placement = place_word(word, start)
            if placement is None:
                continue

            if len(placement) == 0:
                continue  # Word is entirely within known cribs

            # Combine with known keystream
            combined = dict(combined_base)
            for pos, (ch, kv) in placement.items():
                combined[pos] = kv

            scores = score_key_pattern(combined)

            result = {
                'word': word,
                'start': start,
                'end': start + len(word),
                'n_new': len(placement),
                'new_positions': {str(p): (ch, kv) for p, (ch, kv) in placement.items()},
                'scores': scores,
            }
            all_results.append(result)

    print(f"\n  Total valid placements: {len(all_results)}")
    elapsed_place = time.time() - t0
    print(f"  Placement time: {elapsed_place:.1f}s")

    # Sort by various criteria
    # 1. Lowest entropy (most structured key)
    by_entropy = sorted(all_results, key=lambda r: r['scores']['entropy'])

    # 2. Best period-7 consistency
    def p7_score(r):
        consistent, constrained = r['scores']['period_scores'].get(7, (0, 0))
        return -consistent  # negative for sorting (more is better)
    by_period7 = sorted(all_results, key=p7_score)

    # 3. Most zeros (self-encrypting)
    by_zeros = sorted(all_results, key=lambda r: -r['scores']['n_zeros'])

    # 4. Highest max_run
    by_run = sorted(all_results, key=lambda r: -r['scores']['max_run'])

    print(f"\n{'='*60}")
    print("TOP RESULTS BY ENTROPY (lowest = most structured key)")
    print(f"{'='*60}")
    for r in by_entropy[:15]:
        sc = r['scores']
        print(f"  {r['word']:25s} pos {r['start']:2d}-{r['end']:2d}  "
              f"entropy={sc['entropy']:.3f}  "
              f"zeros={sc['n_zeros']}  "
              f"p7={sc['period_scores'][7][0]}/{sc['period_scores'][7][1]}  "
              f"key_text={sc['key_text'][:30]}...")

    print(f"\n{'='*60}")
    print("TOP RESULTS BY PERIOD-7 CONSISTENCY")
    print(f"{'='*60}")
    for r in by_period7[:15]:
        sc = r['scores']
        p7c, p7n = sc['period_scores'][7]
        print(f"  {r['word']:25s} pos {r['start']:2d}-{r['end']:2d}  "
              f"p7={p7c}/{p7n}  "
              f"entropy={sc['entropy']:.3f}  "
              f"key_text={sc['key_text'][:30]}...")

    print(f"\n{'='*60}")
    print("TOP RESULTS BY SELF-ENCRYPTION (key=0)")
    print(f"{'='*60}")
    for r in by_zeros[:15]:
        sc = r['scores']
        if sc['n_zeros'] <= 2:
            break
        print(f"  {r['word']:25s} pos {r['start']:2d}-{r['end']:2d}  "
              f"zeros={sc['n_zeros']}  "
              f"entropy={sc['entropy']:.3f}  "
              f"key_text={sc['key_text'][:30]}...")

    print(f"\n{'='*60}")
    print("TOP RESULTS BY MAX RUN (consecutive equal key values)")
    print(f"{'='*60}")
    for r in by_run[:15]:
        sc = r['scores']
        if sc['max_run'] <= 2:
            break
        print(f"  {r['word']:25s} pos {r['start']:2d}-{r['end']:2d}  "
              f"max_run={sc['max_run']}  "
              f"entropy={sc['entropy']:.3f}  "
              f"key_text={sc['key_text'][:30]}...")

    # Special analysis: words adjacent to known cribs
    print(f"\n{'='*60}")
    print("WORDS ADJACENT TO KNOWN CRIBS")
    print(f"{'='*60}")

    # Right after ENE (pos 34+)
    print("\n  After EASTNORTHEAST (pos 34+):")
    for r in all_results:
        if r['start'] >= 34 and r['start'] <= 40 and r['n_new'] >= 3:
            sc = r['scores']
            # Show the new key values
            new_keys = {int(k): v for k, v in r['new_positions'].items()}
            new_sorted = sorted(new_keys.items())
            key_fragment = ''.join(chr(65 + kv) for pos, (ch, kv) in new_sorted)
            print(f"    {r['word']:20s} pos {r['start']}-{r['end']-1}  "
                  f"new_key={key_fragment}  "
                  f"p7={sc['period_scores'][7][0]}/{sc['period_scores'][7][1]}")

    # Left of ENE (pos 0-20)
    print("\n  Before EASTNORTHEAST (ending at pos 20):")
    for r in all_results:
        if r['end'] >= 18 and r['end'] <= 21 and r['n_new'] >= 3:
            sc = r['scores']
            new_keys = {int(k): v for k, v in r['new_positions'].items()}
            new_sorted = sorted(new_keys.items())
            key_fragment = ''.join(chr(65 + kv) for pos, (ch, kv) in new_sorted)
            print(f"    {r['word']:20s} pos {r['start']}-{r['end']-1}  "
                  f"new_key={key_fragment}  "
                  f"p7={sc['period_scores'][7][0]}/{sc['period_scores'][7][1]}")

    # Right after BC (pos 74+)
    print("\n  After BERLINCLOCK (pos 74+):")
    for r in all_results:
        if r['start'] >= 74 and r['start'] <= 80 and r['n_new'] >= 3:
            sc = r['scores']
            new_keys = {int(k): v for k, v in r['new_positions'].items()}
            new_sorted = sorted(new_keys.items())
            key_fragment = ''.join(chr(65 + kv) for pos, (ch, kv) in new_sorted)
            print(f"    {r['word']:20s} pos {r['start']}-{r['end']-1}  "
                  f"new_key={key_fragment}  "
                  f"p7={sc['period_scores'][7][0]}/{sc['period_scores'][7][1]}")

    # Left of BC (ending at pos 62)
    print("\n  Before BERLINCLOCK (ending at pos 62):")
    for r in all_results:
        if r['end'] >= 58 and r['end'] <= 63 and r['n_new'] >= 3:
            sc = r['scores']
            new_keys = {int(k): v for k, v in r['new_positions'].items()}
            new_sorted = sorted(new_keys.items())
            key_fragment = ''.join(chr(65 + kv) for pos, (ch, kv) in new_sorted)
            print(f"    {r['word']:20s} pos {r['start']}-{r['end']-1}  "
                  f"new_key={key_fragment}  "
                  f"p7={sc['period_scores'][7][0]}/{sc['period_scores'][7][1]}")

    # Check: do ANY placements produce key fragments that are English words?
    print(f"\n{'='*60}")
    print("KEY FRAGMENTS THAT ARE ENGLISH WORDS")
    print(f"{'='*60}")
    english_key_hits = []
    for r in all_results:
        if r['n_new'] >= 3:
            new_keys = {int(k): v for k, v in r['new_positions'].items()}
            new_sorted = sorted(new_keys.items())
            key_fragment = ''.join(chr(65 + kv) for pos, (ch, kv) in new_sorted)
            # Check substrings of length 3+
            for length in range(min(6, len(key_fragment)), 2, -1):
                for start in range(len(key_fragment) - length + 1):
                    substr = key_fragment[start:start+length]
                    if substr in english_words:
                        english_key_hits.append((r, substr, start, length))

    if english_key_hits:
        # Sort by fragment length (longer = more interesting)
        english_key_hits.sort(key=lambda x: -x[3])
        seen = set()
        for r, fragment, fstart, flen in english_key_hits[:30]:
            key = (r['word'], r['start'], fragment)
            if key in seen:
                continue
            seen.add(key)
            new_keys = {int(k): v for k, v in r['new_positions'].items()}
            new_sorted = sorted(new_keys.items())
            full_key = ''.join(chr(65 + kv) for pos, (ch, kv) in new_sorted)
            if flen >= 4:
                print(f"  {r['word']:20s} pos {r['start']:2d}-{r['end']-1:2d}  "
                      f"key_fragment='{fragment}' (len {flen}) in '{full_key}'")
    else:
        print("  None found.")

    elapsed = time.time() - t0

    # Baseline: what's the entropy of just the known 24 key values?
    base_key_vals = [KNOWN_KEY[p] for p in sorted(KNOWN_KEY.keys())]
    base_counts = Counter(base_key_vals)
    import math
    base_entropy = -sum((c/24)*math.log2(c/24) for c in base_counts.values())
    print(f"\n  Baseline (24 known keys): entropy={base_entropy:.3f}")
    print(f"  Random expectation: entropy ≈ {math.log2(26):.3f} (uniform over 26)")

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"  Total words tested: {len(words)}")
    print(f"  Total valid placements: {len(all_results)}")
    print(f"  English key fragments found: {len(set((h[0]['word'],h[0]['start'],h[1]) for h in english_key_hits))}")
    print(f"  Time: {elapsed:.1f}s")

    # Verdict
    # Check if any placement produces anomalously low entropy or high period consistency
    best = by_entropy[0] if by_entropy else None
    if best and best['scores']['entropy'] < base_entropy - 0.5:
        verdict = "SIGNAL"
        print(f"\n  SIGNAL: {best['word']} at pos {best['start']} reduces entropy by "
              f"{base_entropy - best['scores']['entropy']:.3f}")
    else:
        verdict = "NOISE"
        print(f"\n  No placement significantly reduces key entropy below baseline.")
        print(f"  Verdict: NOISE (under identity transposition assumption)")

    # Save results
    os.makedirs("results", exist_ok=True)

    # Save top 100 by each criterion
    save_data = {
        'experiment': 'E-S-43',
        'n_words': len(words),
        'n_placements': len(all_results),
        'n_english_key_hits': len(english_key_hits),
        'baseline_entropy': round(base_entropy, 3),
        'verdict': verdict,
        'elapsed_seconds': round(elapsed, 1),
        'top_by_entropy': [{'word': r['word'], 'start': r['start'], 'end': r['end'],
                           'entropy': r['scores']['entropy'], 'key_text': r['scores']['key_text'][:40],
                           'n_zeros': r['scores']['n_zeros'],
                           'p7': r['scores']['period_scores'][7]}
                          for r in by_entropy[:50]],
        'top_by_period7': [{'word': r['word'], 'start': r['start'], 'end': r['end'],
                           'p7': r['scores']['period_scores'][7],
                           'entropy': r['scores']['entropy']}
                          for r in by_period7[:30]],
        'english_key_fragments': [{'word': r['word'], 'start': r['start'],
                                   'fragment': frag, 'frag_len': flen}
                                  for r, frag, _, flen in english_key_hits[:50]],
    }

    with open("results/e_s_43_thematic_extension.json", "w") as f:
        json.dump(save_data, f, indent=2)

    print(f"\n  Artifact: results/e_s_43_thematic_extension.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_43_thematic_extension.py")


if __name__ == "__main__":
    main()
