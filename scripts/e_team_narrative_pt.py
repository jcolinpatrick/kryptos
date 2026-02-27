#!/usr/bin/env python3
"""
E-TEAM-NARRATIVE: K4 Narrative Plaintext Hypothesis Tester

Generates candidate K4 plaintexts from narrative/thematic analysis,
then evaluates the implied keystream under Vigenère, Beaufort, and
Variant Beaufort. Looks for structure in the keystream: English-likeness,
periodicity, word fragments, artifact matches, and pattern regularity.

Key constraint: All 21 Bean inequalities involve only crib positions
(21-33 and 63-73), so they are AUTOMATICALLY SATISFIED regardless of
candidate plaintext. The discriminator is keystream structure.

Known keystream fragments (Vigenère):
  Pos 21-33: BLZCDCYYGCKAZ  (vowel ratio 7.7%, strongly non-English)
  Pos 63-73: MUYKLGKORNA    (vowel ratio 27.3%, marginal)

Under direct correspondence (no transposition), the running key
hypothesis is already eliminated — these fragments cannot be English.
This script tests for OTHER kinds of keystream structure.

Usage: PYTHONPATH=src python3 -u scripts/e_team_narrative_pt.py
"""

import sys, os, json, math, statistics
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CRIB_WORDS, BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    KRYPTOS_ALPHABET,
)

# ── Constants ────────────────────────────────────────────────────────────
CT_STR = CT
assert len(CT_STR) == 97

CRIB1 = "EASTNORTHEAST"  # pos 21-33
CRIB2 = "BERLINCLOCK"    # pos 63-73
PREFIX_LEN = 21   # positions 0-20
MIDDLE_LEN = 29   # positions 34-62
SUFFIX_LEN = 23   # positions 74-96

# English letter frequencies
ENG_FREQ = {
    'A': .082, 'B': .015, 'C': .028, 'D': .043, 'E': .127, 'F': .022,
    'G': .020, 'H': .061, 'I': .070, 'J': .002, 'K': .008, 'L': .040,
    'M': .024, 'N': .067, 'O': .075, 'P': .019, 'Q': .001, 'R': .060,
    'S': .063, 'T': .091, 'U': .028, 'V': .010, 'W': .023, 'X': .002,
    'Y': .020, 'Z': .001,
}
VOWELS = set('AEIOU')

# ── Load quadgrams ──────────────────────────────────────────────────────
QUAD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         '..', 'data', 'english_quadgrams.json')
with open(QUAD_PATH) as f:
    QUADS = json.load(f)
QUAD_FLOOR = min(QUADS.values()) - 1.0

# ── Load wordlist ───────────────────────────────────────────────────────
WORD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         '..', 'wordlists', 'english.txt')
with open(WORD_PATH) as f:
    ALL_WORDS = set(w.strip().upper() for w in f if len(w.strip()) >= 4)
# For keystream word detection, use only common words (5+ chars)
COMMON_WORDS = {w for w in ALL_WORDS if len(w) >= 5}

# ── Known reference texts for keystream matching ────────────────────────
# K1-K3 plaintexts, Kryptos alphabet, key segments
REFERENCE_TEXTS = {
    'K1_PT': 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUA NCEOFIQLUSION'.replace(' ', ''),
    'K2_PT': ('ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHE'
              'EARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDAND'
              'TRANSMITTEDUNDERGROUNDTOANUNKNOWNLOCATIONXDOES'
              'LANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIED'
              'OUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLY'
              'WWTHISWASHISLASTMESSAGEX'
              'THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINT'
              'FIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES'
              'FORTYFOURSECONDSWESXLAYERTWO').replace(' ', ''),
    'K3_PT': ('SLOWLYDESPERATELYSLOWLYTHEREMAINSOFPASSAGEDEBRIS'
              'THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASR EMOVED'
              'WITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFT'
              'HANDCORNERANDTHENWIDENIN GTHEHOLEALITTLEIINSERTED'
              'THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE'
              'CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS'
              'OFTHEROOMWITHINEMER GEDFROMTHEMISTXCANYOUSEEANYTHINGQ').replace(' ', ''),
    'KRYPTOS_ALPHA': KRYPTOS_ALPHABET,
    'KRYPTOS_ALPHA_X2': KRYPTOS_ALPHABET * 4,  # repeated
}

# ── Utility functions ───────────────────────────────────────────────────

def quadgram_score(text):
    """Average quadgram log-probability per quadgram."""
    n = len(text)
    if n < 4:
        return QUAD_FLOOR
    total = sum(QUADS.get(text[i:i+4], QUAD_FLOOR) for i in range(n - 3))
    return total / (n - 3)


def ic(text):
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def vowel_ratio(text):
    """Fraction of vowels in text."""
    if not text:
        return 0.0
    return sum(1 for c in text if c in VOWELS) / len(text)


def freq_correlation(text):
    """Pearson correlation of letter frequencies with English."""
    n = len(text)
    if n == 0:
        return 0.0
    counts = Counter(text)
    obs = [counts.get(c, 0) / n for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']
    eng = [ENG_FREQ[c] for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']
    mx = statistics.mean(obs)
    my = statistics.mean(eng)
    num = sum((o - mx) * (e - my) for o, e in zip(obs, eng))
    den_x = sum((o - mx) ** 2 for o in obs) ** 0.5
    den_y = sum((e - my) ** 2 for e in eng) ** 0.5
    den = den_x * den_y
    return num / den if den > 0 else 0.0


def find_words(text, min_len=5):
    """Find dictionary words in text (non-overlapping, longest first)."""
    found = []
    used = set()
    for length in range(min(len(text), 13), min_len - 1, -1):
        for i in range(len(text) - length + 1):
            if any(j in used for j in range(i, i + length)):
                continue
            w = text[i:i + length]
            if w in COMMON_WORDS:
                found.append((i, w))
                used.update(range(i, i + length))
    return sorted(found)


def derive_keystream(ct, pt, mode):
    """Derive keystream from CT and PT under given cipher mode."""
    key = []
    for c, p in zip(ct, pt):
        ci, pi = ord(c) - 65, ord(p) - 65
        if mode == 'vig':
            ki = (ci - pi) % 26
        elif mode == 'beau':
            ki = (ci + pi) % 26
        elif mode == 'varbeau':
            ki = (pi - ci) % 26
        else:
            raise ValueError(f"Unknown mode: {mode}")
        key.append(chr(ki + 65))
    return ''.join(key)


def check_periodicity(keystream, max_period=26):
    """Check IC within period classes for signs of periodic key."""
    results = {}
    n = len(keystream)
    for p in range(2, min(max_period + 1, n)):
        # IC within each residue class
        ics = []
        for r in range(p):
            chars = keystream[r::p]
            if len(chars) >= 2:
                ics.append(ic(chars))
        avg_ic = statistics.mean(ics) if ics else 0
        results[p] = avg_ic
    return results


def match_reference(keystream, ref_name, ref_text):
    """Check if keystream matches any position in a reference text."""
    best_match = 0
    best_offset = -1
    ks_len = len(keystream)
    ref_len = len(ref_text)

    for offset in range(ref_len - ks_len + 1):
        matches = sum(1 for i in range(ks_len) if keystream[i] == ref_text[offset + i])
        if matches > best_match:
            best_match = matches
            best_offset = offset
    return best_match, best_offset


def make_plaintext(prefix, middle, suffix):
    """Assemble candidate plaintext and validate."""
    if len(prefix) != PREFIX_LEN:
        raise ValueError(f"Prefix length {len(prefix)}, expected {PREFIX_LEN}: '{prefix}'")
    if len(middle) != MIDDLE_LEN:
        raise ValueError(f"Middle length {len(middle)}, expected {MIDDLE_LEN}: '{middle}'")
    if len(suffix) != SUFFIX_LEN:
        raise ValueError(f"Suffix length {len(suffix)}, expected {SUFFIX_LEN}: '{suffix}'")

    pt = prefix + CRIB1 + middle + CRIB2 + suffix
    assert len(pt) == 97, f"PT length {len(pt)}"
    assert pt.isalpha() and pt.isupper(), f"PT contains invalid characters"
    return pt


# ── Candidate Generation ───────────────────────────────────────────────

def make_segments(phrase, target_len, label=""):
    """Strip spaces/punctuation from phrase and verify length."""
    clean = ''.join(c.upper() for c in phrase if c.isalpha())
    if len(clean) != target_len:
        print(f"  WARNING [{label}]: '{phrase}' -> {len(clean)} chars, need {target_len}")
        return None
    return clean


# Each candidate: (prefix_phrase, middle_phrase, suffix_phrase, description)
# Characters are stripped and uppercased; lengths must be exact.
RAW_CANDIDATES = [
    # ── Theme 1: Answering "Can you see anything?" ──────────────────
    ("OUT OF THE MIST I COULD SEE",                        # 21
     "AN ANCIENT PATH LEADING TOWARD THE",                 # 29
     "WHERE ALL THE NATIONS WATCH",                        # 23
     "K3 answer: mist → ancient path → nations watch"),

    ("DETAILS EMERGED FROM THE",                           # 21
     "MIST A DIRECTION THAT LEADS PAST TH",                # 29
     "E TO THE PLACE WHERE IT ENDS",                       # 23
     "K3 continuation: details emerge, direction leads"),

    ("I COULD SEE A LIGHT HEADIN",                         # 21
     "G THROUGH THE RUINS TO THE PLACE OF T",              # 29
     "HE WHERE THE HANDS SHOW TIME",                       # 23
     "K3 vision: light heading through ruins to clock"),

    ("SLOWLY I SAW FAR OFF TO THE",                        # 21
     "HORIZON WHERE ONCE A WALL DIVIDED TH",               # 29
     "E CITY NOW OPEN TO THE WORLD",                       # 23
     "K3 pace: slowly saw horizon, wall divided city"),

    ("YES I COULD SEE FAR TO THE",                         # 21
     "PLACE WHERE WALLS ONCE STOOD BEYOND T",              # 29
     "HE SQUARE WHERE TIME IS TOLD",                       # 23
     "Carter's answer reframed: yes, far to the east"),

    # ── Theme 2: Intelligence/tradecraft ────────────────────────────
    ("WEBSTERS LAST MESSAGE TO A",                         # 21
     "GENT AT THE WALL DELIVERED VIA THE WO",              # 29
     "RLD WHICH STANDS IN THE CENTRE",                     # 23
     "WW's last message to agent at the Wall"),

    ("TRANSMITTING FROM SITE TO",                          # 21
     "THE OTHER SIDE ACROSS THE FALLEN WALL",              # 29
     "AT TWENTY TWO HUNDRED HOURS",                        # 23
     "Operational: transmitting across fallen wall"),

    ("THE COORDINATES POINT TO",                           # 21
     "A DEAD DROP LOCATED BEYOND THE WORLD",               # 29
     "IN ALEXANDERPLATZ SQUARE X",                         # 23
     "Dead drop at Alexanderplatz (Weltzeituhr)"),

    ("HIS FINAL TRANSMISSION R",                           # 21
     "AN THROUGH THE UNDERGROUND TO REACH T",              # 29
     "HE STANDING IN THE COLD NIGHT",                      # 23
     "WW's final transmission underground"),

    # ── Theme 3: Egypt → Berlin journey ─────────────────────────────
    ("FROM THE BURIAL CHAMBER I",                          # 21
     "SAW THE WAY TO THE FALLEN WALL BY THE",              # 29
     "X STANDING IN THE SQUARE NOW",                       # 23
     "Tomb → Wall → Clock journey"),

    ("IT CAME FROM THE TOMBS OF T",                        # 21
     "HE ANCIENT KINGS PAST THE FALLEN WA",                # 29
     "LL TO THE WORLD CLOCK THAT ST",                      # 23
     "Egyptian tombs → fallen wall → clock"),

    ("FROM EGYPT ACROSS TOWARD",                           # 21
     "THE CITY WHERE ONCE A WALL STOOD BET",               # 29
     "WEEN FREEDOM AND TYRANNY NOW",                       # 23
     "Egypt → Berlin: wall between freedom/tyranny"),

    ("ACROSS TIME AND SPACE THE",                          # 21
     "SECRET TRAVELED FROM THE ANCIENT TOM",               # 29
     "BS TO WHERE THE CLOCK NOW TURN",                     # 23
     "Secret traveled from tombs to clock"),

    ("LIKE CARTER PEERED IN THE",                          # 21
     "DARKENED CHAMBER SO I PEERED PAST TH",               # 29
     "E WALL TO SEE WHAT TIME TELLS",                      # 23
     "Carter parallel: peered in → peered past wall"),

    # ── Theme 4: Berlin Wall specific ───────────────────────────────
    ("ON THE NINTH OF NOVEMBER I",                         # 21
     "STOOD AT THE FALLEN WALL BEYOND THE",                # 29
     "A TIME OF CHANGE AND FREEDOM",                       # 23
     "Nov 9 1989: stood at fallen wall"),

    ("NOVEMBER NINE NINETEEN E",                           # 21
     "IGHTY NINE A WALL FELL NEAR THE WORL",               # 29
     "D WHERE TIME STANDS FOR ALL X",                      # 23
     "November 9 1989: wall fell near Weltzeituhr"),

    ("THE WALL CAME DOWN AND I C",                         # 21
     "OULD SEE THE WORLD BEYOND WHERE THE W",              # 29
     "ORLD TURNS AND TIME IS SHOWN",                       # 23
     "Wall fell, world beyond revealed"),

    # ── Theme 5: Self-referential / meta ────────────────────────────
    ("THIS IS THE LAST PART OF T",                         # 21
     "HE MESSAGE THAT WAS HIDDEN UNDER GRO",               # 29
     "UND THE SECRET IS NOW REVEALED",                     # 23
     "Self-ref: last part of hidden message"),

    ("THE MESSAGE HAS BEEN DELI",                          # 21
     "VERED THROUGH LAYERS OF TIME TO THE W",              # 29
     "ORLD NOW YOU SEE THE DELIVERY",                      # 23
     "Self-ref: message delivered through time"),

    ("BETWEEN THE TOMB AND WALL",                          # 21
     "LIES THE TRUTH THAT TIME REVEALS AND",                # 29
     "THE POINT IS YOU CAN SEE IT",                        # 23
     "Synthesis: tomb/wall/truth/point/seeing"),

    # ── Theme 6: Physical/compass/geographic ────────────────────────
    ("THE POINT IS WHERE YOU TUR",                         # 21
     "N THE COMPASS AND FOLLOW THE DIRECTIO",              # 29
     "N SHOWN BY THE WORLD TIME NOW",                      # 23
     "Compass bearing + world clock"),

    ("FOLLOW THE DIRECTIONS GO",                           # 21
     "PAST THE MARKER WHERE THE PASSAGE LEA",              # 29
     "DS THROUGH TO THE OTHER SIDE",                       # 23
     "Route cipher: follow directions through"),

    ("IT WAS HIDDEN BENEATH THE",                          # 21
     "CORNER OF THE CHAMBER AND PAST THE W",               # 29
     "ALL IT WAITS TO BE DISCOVERED",                      # 23
     "Hidden beneath, past the wall, waiting"),

    # ── Theme 7: What's the point? ──────────────────────────────────
    ("WHAT IS THE POINT THAT HI",                          # 21
     "DES WITHIN THE CIPHER THE ANSWER IS T",              # 29
     "HE TIME AND PLACE YOU FIND IT",                      # 23
     "What's the point: time and place"),

    ("THE POINT OF IT ALL IS THE",                         # 21
     "MOMENT WHEN THE BARRIER FALLS AND THE",              # 29
     "MESSAGE REACHES ITS END NOW",                        # 23
     "The point: barrier falls, message reaches end"),

    # ── Theme 8: Coordinates / dates ────────────────────────────────
    ("THIRTY EIGHT FIFTY SEVEN",                           # 21
     "DEGREES NORTH TO THE PLACE WHERE THE",               # 29
     "ANSWER LIES BURIED OUT THERE",                       # 23
     "K2 coordinates → buried answer"),

    # ── Theme 9: "Not a math solution" / creativity ─────────────────
    ("CREATIVITY IS THE KEY NOT",                          # 21
     "MATHEMATICS THE ANSWER COMES FROM THE",              # 29
     "WORLD AROUND YOU LOOK AND SEE",                      # 23
     "Sanborn: not math, creativity"),

    # ── Theme 10: Delivering a message ──────────────────────────────
    ("A MESSAGE IS BEING SENT T",                          # 21
     "HROUGH TIME FROM THE ANCIENT WORLD T",               # 29
     "O THE MODERN AGE RECEIVE IT X",                      # 23
     "Message delivery across time"),

    ("THE DELIVERY IS COMPLETE",                           # 21
     "D THE MESSAGE TRAVELED FROM TOMB TO W",              # 29
     "ALL AND ARRIVES HERE AT LAST X",                     # 23
     "Delivery complete: tomb → wall → here"),

    # ── Theme 11: Specific Sanborn quotes ───────────────────────────
    ("WHO SAYS IT IS EVEN A MAT",                          # 21
     "H SOLUTION THE ANSWER IS FOUND IN THE",              # 29
     "WORLD AROUND THE SCULPTURE X",                       # 23
     "Sanborn quote: not even a math solution"),

    # ── Theme 12: Wild cards ────────────────────────────────────────
    ("BURIED FOR CENTURIES THE",                           # 21
     "SECRET OF THE PHARAOHS NOW LEADS TO T",              # 29
     "HE PLACE WHERE FREEDOM BEGAN",                      # 23
     "Pharaohs secret → freedom"),

    ("THE CANDLE FLICKERED AND",                           # 21
     "I PEERED PAST THE CHAMBER TOWARD THE",               # 29
     "DAWN OF A NEW ERA IN HISTORY",                       # 23
     "K3 candle → new era (Wall fall)"),

    ("PALIMPSEST ABSCISSA NOW",                            # 21
     "THE FINAL LAYER IS REVEALED BY THE WO",              # 29
     "RLD THE ANSWER WAS ALWAYS HERE",                     # 23
     "K1+K2 keywords → final layer revealed"),

    ("CAN YOU SEE ANYTHING YET",                           # 21
     "I CAN SEE FAR TO THE HORIZON WHERE TH",              # 29
     "E WALL ONCE STOOD NOW FALLEN",                       # 23
     "K3 question echoed + answered"),

    ("ONLY WW KNOWS WHERE IT IS",                          # 21
     "BURIED THE MESSAGE TRAVELED FROM THE",               # 29
     "TOMB TO THE FALLEN WALL HERE",                       # 23
     "WW reference from K2 + tomb/wall"),
]

# ── Main Analysis ───────────────────────────────────────────────────────

def analyze_candidate(idx, prefix, middle, suffix, desc):
    """Full analysis of one candidate plaintext."""
    try:
        pt = make_plaintext(prefix, middle, suffix)
    except (ValueError, AssertionError) as e:
        return None, str(e)

    results = {}

    for mode in ['vig', 'beau', 'varbeau']:
        ks = derive_keystream(CT_STR, pt, mode)

        # Basic metrics
        qs = quadgram_score(ks)
        ic_val = ic(ks)
        vr = vowel_ratio(ks)
        fc = freq_correlation(ks)
        words = find_words(ks)

        # Check periodicity (elevated IC in residue classes)
        period_ics = check_periodicity(ks)
        best_period = max(period_ics, key=period_ics.get)
        best_period_ic = period_ics[best_period]

        # Check reference text matching
        ref_matches = {}
        for rname, rtext in REFERENCE_TEXTS.items():
            if len(rtext) >= 97:
                m, o = match_reference(ks, rname, rtext)
                ref_matches[rname] = (m, o)

        # Check for runs of same letter (cipher structure indicator)
        max_run = 1
        cur_run = 1
        for i in range(1, len(ks)):
            if ks[i] == ks[i-1]:
                cur_run += 1
                max_run = max(max_run, cur_run)
            else:
                cur_run = 1

        # Check for the letter A (key=0, meaning CT=PT)
        a_count = ks.count('A')

        results[mode] = {
            'keystream': ks,
            'quadgram': qs,
            'ic': ic_val,
            'vowel_ratio': vr,
            'freq_corr': fc,
            'words': words,
            'best_period': best_period,
            'best_period_ic': best_period_ic,
            'ref_matches': ref_matches,
            'max_run': max_run,
            'a_count': a_count,
        }

    return pt, results


def print_report(idx, pt, desc, results):
    """Print analysis report for one candidate."""
    print(f"\n{'='*80}")
    print(f"CANDIDATE {idx}: {desc}")
    print(f"{'='*80}")
    print(f"PT: {pt[:21]}|{pt[21:34]}|{pt[34:63]}|{pt[63:74]}|{pt[74:]}")
    print(f"    {'~'*21} {'~'*13} {'~'*29} {'~'*11} {'~'*23}")
    print(f"    prefix         CRIB1         middle              CRIB2    suffix")

    for mode_name, mode_key in [('Vigenère', 'vig'), ('Beaufort', 'beau'),
                                 ('Var.Beaufort', 'varbeau')]:
        r = results[mode_key]
        print(f"\n  [{mode_name}]")
        print(f"  Keystream: {r['keystream']}")
        print(f"  Quadgram:  {r['quadgram']:.3f}  (English≈-3.08, random≈-5.3)")
        print(f"  IC:        {r['ic']:.4f}  (English≈0.067, random≈0.038)")
        print(f"  Vowels:    {r['vowel_ratio']:.1%}  (English≈40%, random≈23%)")
        print(f"  Freq corr: {r['freq_corr']:.3f}  (English≈1.0, random≈0.0)")
        print(f"  A (CT=PT): {r['a_count']}/97")
        print(f"  Max run:   {r['max_run']}")

        if r['words']:
            word_str = ', '.join(f"{w}@{i}" for i, w in r['words'])
            print(f"  Words:     {word_str}")
        else:
            print(f"  Words:     (none >= 5 chars)")

        if r['best_period_ic'] > 0.05:
            print(f"  Period:    p={r['best_period']} IC={r['best_period_ic']:.4f} *ELEVATED*")

        for rname, (m, o) in r['ref_matches'].items():
            if m >= 8:
                print(f"  RefMatch:  {rname}: {m}/97 at offset {o}")


def main():
    print("K4 Narrative Plaintext Hypothesis Tester")
    print("=" * 80)
    print(f"CT: {CT_STR}")
    print(f"Known cribs: EASTNORTHEAST@21, BERLINCLOCK@63")
    print(f"Testing {len(RAW_CANDIDATES)} candidate plaintexts")
    print(f"Wordlist: {len(COMMON_WORDS)} words (5+ chars)")
    print(f"Quadgrams: {len(QUADS)} entries")

    # Verify known keystream fragments
    known_vig = ''.join(chr(v + 65) for v in VIGENERE_KEY_ENE)
    known_vig2 = ''.join(chr(v + 65) for v in VIGENERE_KEY_BC)
    print(f"\nKnown Vigenère keystream:")
    print(f"  Pos 21-33: {known_vig}")
    print(f"  Pos 63-73: {known_vig2}")

    # All Bean constraints are within crib positions — verify
    all_bean_pos = set()
    for a, b in BEAN_EQ:
        all_bean_pos.update([a, b])
    for a, b in BEAN_INEQ:
        all_bean_pos.update([a, b])
    crib_pos = set(range(21, 34)) | set(range(63, 74))
    non_crib_bean = all_bean_pos - crib_pos
    if non_crib_bean:
        print(f"\n  WARNING: Bean positions outside cribs: {non_crib_bean}")
    else:
        print(f"\n  CONFIRMED: All Bean constraints involve only crib positions")
        print(f"  → Bean is NOT a discriminator for candidate plaintexts")

    # Process candidates
    all_results = []
    errors = []

    for idx, (prefix_raw, middle_raw, suffix_raw, desc) in enumerate(RAW_CANDIDATES):
        prefix = make_segments(prefix_raw, PREFIX_LEN, f"C{idx} prefix")
        middle = make_segments(middle_raw, MIDDLE_LEN, f"C{idx} middle")
        suffix = make_segments(suffix_raw, SUFFIX_LEN, f"C{idx} suffix")

        if prefix is None or middle is None or suffix is None:
            errors.append((idx, desc, "Length mismatch"))
            continue

        pt, results = analyze_candidate(idx, prefix, middle, suffix, desc)
        if pt is None:
            errors.append((idx, desc, results))
            continue

        print_report(idx, pt, desc, results)
        all_results.append((idx, pt, desc, results))

    # ── Summary Rankings ────────────────────────────────────────────────
    print(f"\n\n{'='*80}")
    print("SUMMARY RANKINGS")
    print(f"{'='*80}")

    if errors:
        print(f"\n  {len(errors)} candidates failed validation:")
        for idx, desc, err in errors:
            print(f"    C{idx}: {desc} — {err}")

    for mode_name, mode_key in [('Vigenère', 'vig'), ('Beaufort', 'beau'),
                                 ('Var.Beaufort', 'varbeau')]:
        print(f"\n  [{mode_name}] — Top 10 by quadgram score:")
        ranked = sorted(all_results,
                       key=lambda x: x[3][mode_key]['quadgram'],
                       reverse=True)
        for rank, (idx, pt, desc, res) in enumerate(ranked[:10], 1):
            r = res[mode_key]
            word_count = len(r['words'])
            words_str = ' '.join(w for _, w in r['words'][:3])
            print(f"    {rank:2d}. C{idx:2d} q={r['quadgram']:.3f} "
                  f"IC={r['ic']:.4f} V={r['vowel_ratio']:.0%} "
                  f"words={word_count} [{words_str}]")
            print(f"        {desc}")

    # ── Cross-candidate keystream analysis ──────────────────────────────
    print(f"\n\n{'='*80}")
    print("CROSS-CANDIDATE ANALYSIS")
    print(f"{'='*80}")

    # Check: what's the BEST quadgram score achievable?
    best_overall = None
    for idx, pt, desc, res in all_results:
        for mode_key in ['vig', 'beau', 'varbeau']:
            qs = res[mode_key]['quadgram']
            if best_overall is None or qs > best_overall[0]:
                best_overall = (qs, idx, mode_key, desc)

    if best_overall:
        qs, idx, mode, desc = best_overall
        print(f"\n  Best overall: C{idx} [{mode}] quadgram={qs:.3f}")
        print(f"  Description: {desc}")
        print(f"  For reference: English text ≈ -3.08, random ≈ -5.3")
        print(f"  Threshold for 'interesting': > -4.84")

    # Check: any candidate produce keystream with IC > 0.05?
    elevated_ic = []
    for idx, pt, desc, res in all_results:
        for mode_key in ['vig', 'beau', 'varbeau']:
            if res[mode_key]['ic'] > 0.050:
                elevated_ic.append((res[mode_key]['ic'], idx, mode_key, desc))
    if elevated_ic:
        elevated_ic.sort(reverse=True)
        print(f"\n  Candidates with elevated IC (>0.05):")
        for ic_val, idx, mode, desc in elevated_ic[:5]:
            print(f"    C{idx} [{mode}] IC={ic_val:.4f} — {desc}")
    else:
        print(f"\n  No candidate produced keystream with IC > 0.050")

    # Check: any candidate produce keystream words 7+ chars?
    long_words = []
    for idx, pt, desc, res in all_results:
        for mode_key in ['vig', 'beau', 'varbeau']:
            for pos, word in res[mode_key]['words']:
                if len(word) >= 7:
                    long_words.append((len(word), word, pos, idx, mode_key, desc))
    if long_words:
        long_words.sort(reverse=True)
        print(f"\n  Keystream words >= 7 chars found:")
        for wlen, word, pos, idx, mode, desc in long_words[:10]:
            print(f"    C{idx} [{mode}] '{word}' ({wlen}) at pos {pos}")
    else:
        print(f"\n  No keystream words >= 7 chars found in any candidate")

    # Baseline: random plaintext keystream quality
    import random
    random.seed(42)
    rand_scores = {'vig': [], 'beau': [], 'varbeau': []}
    for _ in range(1000):
        rand_pt = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(97))
        # Force cribs
        rand_pt = rand_pt[:21] + CRIB1 + rand_pt[34:63] + CRIB2 + rand_pt[74:]
        for mode in ['vig', 'beau', 'varbeau']:
            ks = derive_keystream(CT_STR, rand_pt, mode)
            rand_scores[mode].append(quadgram_score(ks))

    print(f"\n  BASELINE (1000 random plaintexts with correct cribs):")
    for mode_name, mode_key in [('Vigenère', 'vig'), ('Beaufort', 'beau'),
                                 ('Var.Beaufort', 'varbeau')]:
        scores = rand_scores[mode_key]
        print(f"    [{mode_name}] mean={statistics.mean(scores):.3f} "
              f"std={statistics.stdev(scores):.3f} "
              f"max={max(scores):.3f} "
              f"min={min(scores):.3f}")

    print(f"\n{'='*80}")
    print("CONCLUSION")
    print(f"{'='*80}")
    print("""
  Under direct correspondence (no transposition), the known keystream
  fragments BLZCDCYYGCKAZ and MUYKLGKORNA are deterministic regardless
  of candidate plaintext. These fragments:
  - Are NOT English (vowel ratio 7.7%/27.3% vs 40%)
  - Contain no recognizable words
  - Have poor quadgram scores

  Therefore: NO narrative plaintext can produce an English-like keystream
  under direct Vigenère/Beaufort/VarBeau. The running key hypothesis
  (without transposition) remains ELIMINATED for all candidates.

  The value of this analysis is:
  1. Establishing baseline keystream quality for narrative plaintexts
  2. Testing whether any candidate produces unusual keystream structure
  3. Confirming that the cipher MUST involve either:
     a. A transposition layer (disrupting position correspondence), OR
     b. A non-running-key substitution with structured key generation, OR
     c. A fundamentally different cipher model

  Next steps: Test top-scoring candidates WITH transposition layers,
  or use the candidate plaintext structure to constrain transposition search.
""")


if __name__ == '__main__':
    main()
