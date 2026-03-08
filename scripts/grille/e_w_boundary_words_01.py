#!/usr/bin/env python3
"""
Cipher:      W-as-word-boundary hypothesis
Family:      grille
Status:      active
Keyspace:    ~10^12 (combinatorial word fitting)
Last run:    never
Best score:  0

W-as-word-boundary analysis for Kryptos K4.
Hypothesis: the W characters in K4 ciphertext mark word boundaries in the plaintext.
W positions in CT: 20, 36, 48, 58, 74

User-specified segments (include boundary position):
  Seg1: pos 0-20   (21 chars) — unknown
  Seg2: pos 21-36  (16 chars) — EASTNORTHEAST (21-33) + 3 unknown (34-36)
  Seg3: pos 37-48  (12 chars) — unknown
  Seg4: pos 49-58  (10 chars) — unknown
  Seg5: pos 59-74  (16 chars) — 4 unknown (59-62) + BERLINCLOCK (63-73) + 1 unknown (74)
  Seg6: pos 75-96  (22 chars) — unknown
"""
import sys
import os
import itertools
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.transforms.vigenere import (
    vig_recover_key, beau_recover_key, varbeau_recover_key,
    CipherVariant, KEY_RECOVERY, DECRYPT_FN,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.constraints.bean import verify_bean

# ── Constants ────────────────────────────────────────────────────────────────

W_POSITIONS = [20, 36, 48, 58, 74]
CT_NUMS = [ALPH_IDX[c] for c in CT]

# ── Load wordlist ────────────────────────────────────────────────────────────

def load_wordlist(path):
    words = set()
    with open(path) as f:
        for line in f:
            w = line.strip().upper()
            if w and w.isalpha() and len(w) <= 30:
                words.add(w)
    return words

print("Loading wordlist...")
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'english.txt')
ALL_WORDS = load_wordlist(WORDLIST_PATH)
print(f"  Loaded {len(ALL_WORDS)} words")

WORDS_BY_LEN = defaultdict(set)
for w in ALL_WORDS:
    WORDS_BY_LEN[len(w)].add(w)

# ── Verify W positions ──────────────────────────────────────────────────────

print(f"\nCT = {CT}")
print(f"Verifying W positions in CT:")
for p in W_POSITIONS:
    assert CT[p] == 'W', f"CT[{p}] = '{CT[p]}', expected 'W'"
    print(f"  CT[{p}] = 'W'  ✓")

# ═══════════════════════════════════════════════════════════════════════════
# PART 1: SEGMENT WORD FITTING
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 1: SEGMENT WORD FITTING ANALYSIS")
print("="*80)

# ── Segment 2: EASTNORTHEAST + 3 chars (pos 21-36) ─────────────────────────

print("\n--- Segment 2: pos 21-36 (16 chars) ---")
print("Known: EASTNORTHEAST at pos 21-33 (13 chars)")
print("Unknown: pos 34-36 (3 chars)")

# 3-letter words that could follow EASTNORTHEAST
seg2_3letter = sorted(WORDS_BY_LEN[3])
print(f"\nAll 3-letter words: {len(seg2_3letter)}")

# Thematically strong candidates
THEMATIC_3 = sorted([w for w in seg2_3letter if w in {
    # Directional/navigational
    'AIR', 'ARC', 'ARM', 'MAP', 'KEY', 'SKY', 'SUN', 'TOP', 'WAY',
    # Espionage
    'SPY', 'WAR', 'HID', 'LED', 'RAN', 'SAW',
    # Descriptive
    'THE', 'AND', 'FOR', 'NOT', 'ONE', 'TWO', 'SIX', 'TEN',
    'AGO', 'END', 'ERA', 'FAR', 'FEW', 'NEW', 'NOW', 'OLD', 'OUR',
    'OUT', 'OWN', 'RED', 'SET', 'VIA', 'YET',
    # Berlin-related
    'DIE', 'ICE', 'FOG', 'GAS', 'GUN',
    # Time
    'DAY',
}])
print(f"Thematic 3-letter candidates: {len(THEMATIC_3)}")
for w in THEMATIC_3:
    print(f"  EASTNORTHEAST {w}")

# Also check: 2-letter words at pos 34-35 (if pos 36 is just a boundary char)
seg2_2letter = sorted([w for w in WORDS_BY_LEN[2] if w in {
    'AN', 'AT', 'BE', 'BY', 'DO', 'GO', 'HE', 'IF', 'IN', 'IS',
    'IT', 'ME', 'MY', 'NO', 'OF', 'ON', 'OR', 'SO', 'TO', 'UP', 'WE',
}])
print(f"\nIf pos 36 is boundary filler, 2-letter words at pos 34-35:")
for w in seg2_2letter:
    print(f"  EASTNORTHEAST {w} [boundary]")

# ── Segment 5: ????BERLINCLOCK? (pos 59-74) ─────────────────────────────────

print("\n--- Segment 5: pos 59-74 (16 chars) ---")
print("Known: BERLINCLOCK at pos 63-73 (11 chars)")
print("Unknown: pos 59-62 (4 chars) + pos 74 (1 char)")

# 4-letter words before BERLINCLOCK
THEMATIC_4 = sorted([w for w in WORDS_BY_LEN[4] if w in {
    # Prepositions/articles/connectors
    'NEAR', 'FROM', 'ATOP', 'UPON', 'PAST', 'OVER', 'WITH', 'INTO',
    'THAN', 'THAT', 'THIS', 'THEM', 'THEN', 'THEY', 'WHAT', 'WHEN',
    'EACH', 'SOME', 'SUCH', 'ALSO', 'ONLY', 'JUST', 'BACK', 'DOWN',
    'MORE', 'MOST', 'MUCH', 'VERY', 'ONCE', 'HALF',
    # Espionage/navigation
    'FIND', 'SEEK', 'SEEN', 'HIDE', 'TOLD', 'HELD', 'KEPT', 'MARK',
    'LEFT', 'MADE', 'TOOK', 'MOVE', 'SAID', 'KNEW', 'KNOW', 'USED',
    'LOOK', 'FACE', 'OPEN', 'TRUE', 'CLUE', 'CODE',
    # Direction/location
    'EAST', 'WEST', 'SIDE', 'GATE', 'WALL', 'CITY', 'AREA', 'ZONE',
    'SITE', 'GONE', 'DARK', 'COLD', 'DEAD', 'DEEP', 'HERE', 'AWAY',
    'LONG', 'LAST', 'NEXT', 'PART', 'LINE', 'ROAD',
    # Time
    'TIME', 'HOUR', 'FIVE', 'NINE', 'ZERO', 'YEAR',
    # Action
    'STOP', 'TURN', 'HEAD', 'READ', 'HAND', 'PLAN', 'WORK',
    'FAST', 'SLOW', 'HIGH', 'LINK', 'RING', 'ROCK', 'SAFE', 'SIGN',
}])

# Suffix (1 char at pos 74)
# Most likely: S (plural BERLINCLOCKS), or could be part of a different word
print(f"\n4-letter word candidates before BERLINCLOCK: {len(THEMATIC_4)}")
for w in THEMATIC_4[:30]:
    print(f"  {w} BERLINCLOCK ?")

print(f"\n1-char suffix at pos 74 after BERLINCLOCK:")
print("  S → BERLINCLOCKS (plural)")
print("  Other: A, I, E, Y, N, etc. (start of next word if not boundary)")

# Check if segment could be: THE + BERLINCLOCK + S = 3+11+1=15 (need 16 total)
# Or: THEB + ERLINCLOCK + S = doesn't make sense
# Or: word splits differently

# ── Segments 1, 3, 4, 6: Single-word candidates ─────────────────────────────

print("\n--- Segments 1, 3, 4, 6: Unknown segments ---")

for name, start, end, length in [("Seg1", 0, 20, 21), ("Seg3", 37, 48, 12),
                                   ("Seg4", 49, 58, 10), ("Seg6", 75, 96, 22)]:
    ct_slice = CT[start:end+1]
    single = WORDS_BY_LEN[length]
    print(f"\n{name}: pos {start}-{end} ({length} chars), CT='{ct_slice}'")
    print(f"  Single {length}-letter words: {len(single)}")

    # Show thematic matches
    thematic = sorted([w for w in single if any(t in w for t in [
        'SECRET', 'CIPHER', 'CRYPT', 'HIDDEN', 'SHADOW', 'BURIED',
        'CLOCK', 'TIME', 'POINT', 'COORD', 'TRANS', 'ENIGMA',
        'BERLIN', 'AGENT', 'DEFECT', 'INTEL', 'UNDER', 'GROUND',
        'NORTH', 'SOUTH', 'EAST', 'WEST', 'MAGNET', 'STONE',
        'LAYER', 'SCULPT', 'LIGHT', 'DARK', 'NIGHT', 'LOCAT',
        'DIRECT', 'POSIT', 'DEGREE', 'MINUT', 'SECOND', 'LODES',
        'HOROL', 'PARAL',
    ])])
    if thematic:
        print(f"  Thematic single-word candidates ({len(thematic)}):")
        for w in thematic[:20]:
            print(f"    {w}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 2: KEY RECOVERY FROM KNOWN CRIBS
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 2: KEY RECOVERY AT CRIB POSITIONS")
print("="*80)

VARIANTS = {
    "vigenere":     vig_recover_key,
    "beaufort":     beau_recover_key,
    "var_beaufort": varbeau_recover_key,
}

CRIB_POSITIONS = sorted(CRIB_DICT.keys())
print(f"Crib positions ({len(CRIB_POSITIONS)}): {CRIB_POSITIONS}")

for vname, recover_fn in VARIANTS.items():
    keys = {}
    for pos in CRIB_POSITIONS:
        c = ALPH_IDX[CT[pos]]
        p = ALPH_IDX[CRIB_DICT[pos]]
        keys[pos] = recover_fn(c, p)

    key_chars = ''.join(ALPH[keys[p]] for p in CRIB_POSITIONS)
    key_vals = [keys[p] for p in CRIB_POSITIONS]
    print(f"\n  {vname.upper()}: key at cribs = {key_chars}")
    print(f"  Key values: {key_vals}")

    # Check consistency at each period 3-26
    print(f"  Period consistency:")
    for period in range(3, 27):
        residues = defaultdict(set)
        for pos in CRIB_POSITIONS:
            residues[pos % period].add(keys[pos])

        n_conflicts = sum(1 for vals in residues.values() if len(vals) > 1)
        n_covered = len(residues)  # how many residues have at least one value

        if n_conflicts == 0:
            # Build keyword
            kw = ['?'] * period
            for r, vals in residues.items():
                kw[r] = ALPH[list(vals)[0]]
            kw_str = ''.join(kw)
            known_pct = (period - kw_str.count('?')) / period * 100
            print(f"    Period {period}: CONSISTENT — keyword = {kw_str} ({known_pct:.0f}% known, {n_covered}/{period} residues)")

            # Check if keyword is in dictionary
            if '?' not in kw_str and kw_str in ALL_WORDS:
                print(f"      *** DICTIONARY WORD: {kw_str} ***")

# ═══════════════════════════════════════════════════════════════════════════
# PART 3: WHAT DO W POSITIONS DECRYPT TO?
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 3: W-POSITION DECRYPTION ANALYSIS")
print("="*80)

# For each consistent period, decrypt the W positions and see what they become
for vname, recover_fn in VARIANTS.items():
    print(f"\n--- {vname.upper()} ---")

    # Get crib keys
    crib_keys = {}
    for pos in CRIB_POSITIONS:
        c = ALPH_IDX[CT[pos]]
        p = ALPH_IDX[CRIB_DICT[pos]]
        crib_keys[pos] = recover_fn(c, p)

    for period in range(3, 27):
        residues = defaultdict(set)
        for pos in CRIB_POSITIONS:
            residues[pos % period].add(crib_keys[pos])

        n_conflicts = sum(1 for vals in residues.values() if len(vals) > 1)
        if n_conflicts > 0:
            continue  # Skip inconsistent periods

        # Build partial keyword
        kw = {}
        for r, vals in residues.items():
            kw[r] = list(vals)[0]

        # Decrypt W positions
        w_decrypted = []
        all_known = True
        for wp in W_POSITIONS:
            r = wp % period
            if r in kw:
                c = ALPH_IDX[CT[wp]]
                k = kw[r]
                if vname == "vigenere":
                    pt = (c - k) % MOD
                elif vname == "beaufort":
                    pt = (k - c) % MOD
                else:
                    pt = (c + k) % MOD
                w_decrypted.append(ALPH[pt])
            else:
                w_decrypted.append('?')
                all_known = False

        w_str = ''.join(w_decrypted)
        unique = set(w_decrypted) - {'?'}

        if all_known and len(unique) == 1:
            print(f"  Period {period}: ALL W positions → '{list(unique)[0]}' *** SAME LETTER ***")

            # This is significant! Decrypt the full CT where we can
            full_pt = []
            for i in range(97):
                r = i % period
                if r in kw:
                    c = ALPH_IDX[CT[i]]
                    k = kw[r]
                    if vname == "vigenere":
                        pt = (c - k) % MOD
                    elif vname == "beaufort":
                        pt = (k - c) % MOD
                    else:
                        pt = (c + k) % MOD
                    full_pt.append(ALPH[pt])
                else:
                    full_pt.append('?')

            pt_str = ''.join(full_pt)

            # Show with segment markers
            print(f"    PT: {pt_str}")
            segs = []
            seg_start = 0
            for wp in W_POSITIONS:
                segs.append(pt_str[seg_start:wp])
                seg_start = wp + 1
            segs.append(pt_str[seg_start:])
            for i, seg in enumerate(segs):
                print(f"    Seg{i+1}: '{seg}'")

        elif all_known:
            print(f"  Period {period}: W positions → {w_decrypted}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 4: EXHAUSTIVE FULL-KEYWORD SEARCH (periods with all residues known)
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 4: FULL-KEYWORD DECRYPT AND SCORE (periods with <=2 unknown residues)")
print("="*80)

best_results = []

for vname, recover_fn in VARIANTS.items():
    # Get crib keys
    crib_keys = {}
    for pos in CRIB_POSITIONS:
        c = ALPH_IDX[CT[pos]]
        p = ALPH_IDX[CRIB_DICT[pos]]
        crib_keys[pos] = recover_fn(c, p)

    # Determine decrypt function
    if vname == "vigenere":
        dec = lambda c, k: (c - k) % MOD
    elif vname == "beaufort":
        dec = lambda c, k: (k - c) % MOD
    else:
        dec = lambda c, k: (c + k) % MOD

    for period in range(3, 27):
        residues = defaultdict(set)
        for pos in CRIB_POSITIONS:
            residues[pos % period].add(crib_keys[pos])

        n_conflicts = sum(1 for vals in residues.values() if len(vals) > 1)
        if n_conflicts > 0:
            continue

        # Build partial keyword
        kw = {}
        for r, vals in residues.items():
            kw[r] = list(vals)[0]

        missing = [i for i in range(period) if i not in kw]

        if len(missing) > 2:
            continue  # Too many unknowns

        # Enumerate missing residue values
        combos = list(itertools.product(range(26), repeat=len(missing)))

        for combo in combos:
            full_kw = dict(kw)
            for mr, kv in zip(missing, combo):
                full_kw[mr] = kv

            # Decrypt full CT
            pt_chars = []
            for i in range(97):
                c = CT_NUMS[i]
                k = full_kw[i % period]
                pt_chars.append(ALPH[dec(c, k)])
            pt_str = ''.join(pt_chars)

            # Quick checks
            # 1. Do cribs match? (they should by construction)
            # 2. Check IC
            ic_val = ic(pt_str)

            # 3. Check W positions all same letter
            w_chars = [pt_str[wp] for wp in W_POSITIONS]
            w_same = len(set(w_chars)) == 1

            # 4. Build keyword string
            kw_str = ''.join(ALPH[full_kw[i]] for i in range(period))

            # 5. Check if keyword is a word
            is_word = kw_str in ALL_WORDS

            # Score criteria:
            # - High IC (> 0.05 suggests English-like)
            # - W positions all same (supports hypothesis)
            # - Keyword is English word
            composite = 0
            if ic_val > 0.055:
                composite += 3
            elif ic_val > 0.045:
                composite += 1
            if w_same:
                composite += 5
            if is_word:
                composite += 3

            if composite >= 3 or (ic_val > 0.05) or w_same:
                best_results.append({
                    'variant': vname,
                    'period': period,
                    'keyword': kw_str,
                    'plaintext': pt_str,
                    'ic': ic_val,
                    'w_same': w_same,
                    'w_chars': w_chars,
                    'is_word': is_word,
                    'composite': composite,
                })

# Sort by composite score
best_results.sort(key=lambda x: (-x['composite'], -x['ic']))

print(f"\nTotal candidates meeting threshold: {len(best_results)}")

print("\nTop 30 candidates:")
print(f"{'#':>3} {'Comp':>4} {'IC':>6} {'Wsame':>5} {'DictW':>5} {'Var':>12} {'Per':>3} {'Keyword':>26}")
print("-" * 85)

for i, r in enumerate(best_results[:30]):
    w_info = f"all={r['w_chars'][0]}" if r['w_same'] else f"{r['w_chars']}"
    print(f"{i+1:>3} {r['composite']:>4} {r['ic']:>6.4f} {w_info:>8} {'YES' if r['is_word'] else '':>5} {r['variant']:>12} {r['period']:>3} {r['keyword']:>26}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 5: DEEP DIVE ON W-SAME-LETTER CANDIDATES
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 5: DETAILED ANALYSIS OF W-SAME-LETTER CANDIDATES")
print("="*80)

w_same_results = [r for r in best_results if r['w_same']]
print(f"\nCandidates where all 5 W positions decrypt to same letter: {len(w_same_results)}")

for i, r in enumerate(w_same_results[:20]):
    pt = r['plaintext']
    print(f"\n--- Candidate {i+1} ---")
    print(f"  Variant: {r['variant']}, Period: {r['period']}, Keyword: {r['keyword']}")
    print(f"  IC: {r['ic']:.4f}, W-letter: {r['w_chars'][0]}")
    print(f"  Keyword in dictionary: {r['is_word']}")

    # Show segmented plaintext
    segs = []
    seg_start = 0
    for wp in W_POSITIONS:
        segs.append(pt[seg_start:wp])
        seg_start = wp + 1
    segs.append(pt[seg_start:])

    for j, seg in enumerate(segs):
        # Check if segment contains recognizable words
        words_found = []
        for wlen in range(3, len(seg)+1):
            for start in range(len(seg) - wlen + 1):
                substr = seg[start:start+wlen]
                if substr in ALL_WORDS and wlen >= 4:
                    words_found.append((start, substr))

        wf_str = f" → words: {[w for _, w in words_found[:5]]}" if words_found else ""
        print(f"  Seg{j+1} ({len(seg)} chars): '{seg}'{wf_str}")

    # Full scoring
    try:
        # Build keystream for Bean check
        kw_vals = [ALPH_IDX[c] for c in r['keyword']]
        keystream = [kw_vals[i % r['period']] for i in range(97)]
        bean_result = verify_bean(keystream)

        sc = score_candidate(pt, bean_result=bean_result)
        print(f"  Score: {sc.summary}")
    except Exception as e:
        print(f"  Scoring error: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 6: EXHAUSTIVE SMALL-PERIOD ANALYSIS (periods 3-13)
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 6: WHY PERIODS 3-13 ALL HAVE CRIB CONFLICTS")
print("="*80)

for vname, recover_fn in VARIANTS.items():
    print(f"\n--- {vname.upper()} ---")

    crib_keys = {}
    for pos in CRIB_POSITIONS:
        c = ALPH_IDX[CT[pos]]
        p = ALPH_IDX[CRIB_DICT[pos]]
        crib_keys[pos] = recover_fn(c, p)

    for period in range(3, 14):
        residues = defaultdict(set)
        for pos in CRIB_POSITIONS:
            residues[pos % period].add(crib_keys[pos])

        conflicts = [(r, vals) for r, vals in residues.items() if len(vals) > 1]

        if conflicts:
            print(f"  Period {period}: {len(conflicts)} conflict(s)")
            for r, vals in conflicts[:3]:
                positions = [p for p in CRIB_POSITIONS if p % period == r]
                pos_details = [(p, CRIB_DICT[p], CT[p], ALPH[crib_keys[p]]) for p in positions]
                print(f"    Residue {r}: key values {vals} from positions {pos_details}")
        else:
            kw = ''.join(ALPH[list(residues[i])[0]] if i in residues else '?' for i in range(period))
            print(f"  Period {period}: CONSISTENT → {kw}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 7: SCORE ALL FULLY-DETERMINED CANDIDATES WITH FULL INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 7: TOP 10 CANDIDATES WITH FULL SCORING")
print("="*80)

# Score all w_same candidates plus high-IC candidates
to_score = best_results[:100]  # Top 100 by composite

scored_final = []
for r in to_score:
    pt = r['plaintext']
    try:
        kw_vals = [ALPH_IDX[c] for c in r['keyword']]
        keystream = [kw_vals[i % r['period']] for i in range(97)]
        bean_result = verify_bean(keystream)
        sc = score_candidate(pt, bean_result=bean_result)

        r_copy = dict(r)
        r_copy['crib_score'] = sc.crib_score
        r_copy['bean_passed'] = sc.bean_passed
        r_copy['classification'] = sc.crib_classification
        r_copy['ene_score'] = sc.ene_score
        r_copy['bc_score'] = sc.bc_score
        scored_final.append(r_copy)
    except Exception as e:
        pass

scored_final.sort(key=lambda x: (-x['crib_score'], -x['ic']))

print(f"\nScored {len(scored_final)} candidates")
print("\nTop 10:")
print(f"{'#':>2} {'Crib':>4} {'ENE':>3} {'BC':>3} {'IC':>6} {'Bean':>4} {'Wsame':>5} {'Var':>12} {'Per':>3} {'Keyword':>26} {'Class':>15}")
print("-" * 100)

for i, s in enumerate(scored_final[:10]):
    w_info = f"={s['w_chars'][0]}" if s['w_same'] else "no"
    print(f"{i+1:>2} {s['crib_score']:>4} {s['ene_score']:>3} {s['bc_score']:>3} {s['ic']:>6.4f} {'P' if s['bean_passed'] else 'F':>4} {w_info:>5} {s['variant']:>12} {s['period']:>3} {s['keyword']:>26} {s['classification']:>15}")

    # Show plaintext with word boundaries marked
    pt = s['plaintext']
    segs = []
    seg_start = 0
    for wp in W_POSITIONS:
        segs.append(pt[seg_start:wp])
        seg_start = wp + 1
    segs.append(pt[seg_start:])
    print(f"   PT: {' | '.join(segs)}")
    print()

# ═══════════════════════════════════════════════════════════════════════════
# PART 8: REVERSE APPROACH — What plaintext at Seg2/Seg5 unknowns makes
#         the key periodic with a thematic keyword?
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 8: THEMATIC KEYWORD TARGET SEARCH")
print("="*80)

THEMATIC_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE", "DEFECTOR",
    "PARALLAX", "COLOPHON", "SHADOW", "VERDIGRIS", "ENIGMA",
    "BERLIN", "CLOCK", "POINT", "NEEDLE", "COMPASS", "LODESTONE",
    "MAGNETIC", "NORTH", "EAST", "FIVE", "LAYER", "SECRET",
    "MATRIX", "CIPHER", "HIDDEN", "DEGREE", "MINUTE", "SECOND",
    "ANTIPODES", "SANBORN", "SCHEIDT",
]

for keyword in THEMATIC_KEYWORDS:
    period = len(keyword)
    if period > 26:
        continue
    kw_vals = [ALPH_IDX[c] for c in keyword]

    for vname in ["vigenere", "beaufort", "var_beaufort"]:
        # Check: does this keyword + variant produce the known cribs?
        consistent = True
        for pos in CRIB_POSITIONS:
            c = CT_NUMS[pos]
            k = kw_vals[pos % period]
            if vname == "vigenere":
                p = (c - k) % MOD
            elif vname == "beaufort":
                p = (k - c) % MOD
            else:
                p = (c + k) % MOD

            if ALPH[p] != CRIB_DICT[pos]:
                consistent = False
                break

        if consistent:
            # Full decrypt
            pt_chars = []
            for i in range(97):
                c = CT_NUMS[i]
                k = kw_vals[i % period]
                if vname == "vigenere":
                    p = (c - k) % MOD
                elif vname == "beaufort":
                    p = (k - c) % MOD
                else:
                    p = (c + k) % MOD
                pt_chars.append(ALPH[p])

            pt_str = ''.join(pt_chars)
            ic_val = ic(pt_str)
            w_chars = [pt_str[wp] for wp in W_POSITIONS]

            print(f"\n*** KEYWORD '{keyword}' ({vname}) CONSISTENT WITH CRIBS ***")
            print(f"    IC: {ic_val:.4f}")
            print(f"    W positions decrypt to: {w_chars} {'*** ALL SAME ***' if len(set(w_chars))==1 else ''}")

            # Show segments
            segs = []
            seg_start = 0
            for wp in W_POSITIONS:
                segs.append(pt_str[seg_start:wp])
                seg_start = wp + 1
            segs.append(pt_str[seg_start:])
            print(f"    Segments:")
            for j, seg in enumerate(segs):
                # Find English words
                words = []
                for wlen in range(4, min(len(seg)+1, 15)):
                    for start in range(len(seg) - wlen + 1):
                        substr = seg[start:start+wlen]
                        if substr in ALL_WORDS:
                            words.append(substr)
                wf = f" → words: {words[:5]}" if words else ""
                print(f"      Seg{j+1}: '{seg}'{wf}")

            # Score
            keystream = [kw_vals[i % period] for i in range(97)]
            bean_result = verify_bean(keystream)
            sc = score_candidate(pt_str, bean_result=bean_result)
            print(f"    Score: {sc.summary}")

# ═══════════════════════════════════════════════════════════════════════════
# PART 9: STATISTICAL ANALYSIS OF W-POSITION DISTRIBUTION
# ═══════════════════════════════════════════════════════════════════════════

print("\n" + "="*80)
print("PART 9: STATISTICAL ANALYSIS OF W-AS-BOUNDARY HYPOTHESIS")
print("="*80)

# Count W's in CT
w_count = CT.count('W')
print(f"Total W's in CT: {w_count} out of {len(CT)} = {w_count/len(CT)*100:.1f}%")
print(f"Expected if random: {len(CT)/26:.1f} = {100/26:.1f}%")

# Positions of all W's
all_w = [i for i, c in enumerate(CT) if c == 'W']
print(f"All W positions: {all_w}")

# Gaps between consecutive W's
gaps = [all_w[i+1] - all_w[i] for i in range(len(all_w)-1)]
print(f"Gaps between W's: {gaps}")
print(f"Mean gap: {sum(gaps)/len(gaps):.1f}")

# Are the gaps consistent with word lengths?
# English word length distribution: mean ~4.7, mode ~3-4
# The gaps here range from 10-18, which is more like phrase lengths
print(f"\nGap analysis (gap = segment length + 1 for the W itself):")
for i, gap in enumerate(gaps):
    print(f"  W[{all_w[i]}] to W[{all_w[i+1]}]: gap={gap}, content length={gap-1}")
print(f"  Before first W: {all_w[0]} chars")
print(f"  After last W: {len(CT) - all_w[-1] - 1} chars")

# These are too long for single words, suggesting phrases between W's
# Average English word = ~5 chars, so 10-22 char segments = 2-4 words each

print("\nSegment lengths (content between W's):")
content_lengths = [all_w[0]]  # before first W
for i in range(len(all_w)-1):
    content_lengths.append(all_w[i+1] - all_w[i] - 1)
content_lengths.append(len(CT) - all_w[-1] - 1)  # after last W

for i, cl in enumerate(content_lengths):
    est_words = cl / 5.0  # rough estimate
    print(f"  Segment {i+1}: {cl} chars ≈ {est_words:.1f} words")

# Chi-squared test: is the W distribution unusual?
from collections import Counter
letter_counts = Counter(CT)
total = len(CT)
expected = total / 26
print(f"\nLetter frequency analysis:")
print(f"  Expected per letter (uniform): {expected:.1f}")
print(f"  W count: {letter_counts['W']} (expected {expected:.1f})")
print(f"  W excess: {(letter_counts['W'] - expected) / expected * 100:+.1f}%")

# Compare W to other letters
print(f"\n  Top 5 most frequent: {letter_counts.most_common(5)}")
print(f"  Bottom 5 least frequent: {letter_counts.most_common()[-5:]}")

# ── Final Summary ──────────────────────────────────────────────────────────

print("\n" + "="*80)
print("FINAL SUMMARY")
print("="*80)

print(f"""
ANALYSIS COMPLETE: W-as-word-boundary hypothesis for K4.

Key findings:

1. W POSITIONS VERIFIED: CT[20], CT[36], CT[48], CT[58], CT[74] = all 'W'
   - Total W count in CT: {w_count} (5 at specified positions, {w_count-5} elsewhere)
   - Gaps between specified W's: {gaps} (content lengths: {content_lengths})

2. CRIB CONSISTENCY BY PERIOD:
   - Periods 3-13: ALL have crib conflicts for Vigenere, Beaufort, and Var-Beaufort
   - This means NO short periodic keyword works with direct positional correspondence
   - Consistent periods found only at 14+ (where most residues are underdetermined)

3. SEGMENT WORD CANDIDATES:
   - Seg2 (pos 34-36): {len(seg2_3letter)} possible 3-letter words after EASTNORTHEAST
   - Seg5 (pos 59-62): {len(THEMATIC_4)} thematic 4-letter words before BERLINCLOCK
   - Seg5 (pos 74): 1 char after BERLINCLOCK (S for plural, or single-letter word)

4. W-SAME-LETTER CANDIDATES: {len(w_same_results)} found where all 5 W positions
   decrypt to the same plaintext letter (supporting the boundary hypothesis)

5. THEMATIC KEYWORDS: Tested {len(THEMATIC_KEYWORDS)} keywords, showing which are
   crib-consistent and what their W-position behavior is

6. STATISTICAL: W frequency = {letter_counts['W']}/{total} ({letter_counts['W']/total*100:.1f}%)
   vs expected {expected:.1f} ({100/26:.1f}%). Segment lengths (10-22) suggest
   phrase-level boundaries, not single-word boundaries.
""")

print("Script complete.")
