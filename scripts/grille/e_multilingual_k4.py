#!/usr/bin/env python3
"""
Test K4 decryption scored against German and Greek (transliterated) quadgrams.

Hypothesis: "Remove E" from DESPARATLY hints K4 plaintext is NOT English.
Candidates: German (BERLIN connection), Greek (KRYPTOS, URANIA are Greek words).

Phase 1: Generate German/Greek quadgram tables from frequency data
Phase 2: Decrypt K4 with all keyword/cipher combos, score with each language
Phase 3: Compare best scores across languages

Cipher: Vigenere/Beaufort
Family: grille
Status: active
"""
import sys, os, json, math
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD

# ── Load English quadgrams ───────────────────────────────────────────────────
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    QG_EN = json.load(f)
QG_EN_FLOOR = min(QG_EN.values()) - 1.0

# ── German letter frequencies (from large corpus studies) ────────────────────
# Source: standard German letter frequency tables
# German has notably different frequencies: high E, N, I, S, R; low Y, Q, X
GERMAN_FREQ = {
    'E': 0.1639, 'N': 0.0978, 'I': 0.0765, 'S': 0.0727, 'R': 0.0700,
    'A': 0.0651, 'T': 0.0615, 'D': 0.0508, 'H': 0.0476, 'U': 0.0435,
    'L': 0.0344, 'C': 0.0306, 'G': 0.0301, 'M': 0.0253, 'O': 0.0251,
    'B': 0.0189, 'W': 0.0189, 'F': 0.0166, 'K': 0.0121, 'Z': 0.0113,
    'P': 0.0079, 'V': 0.0067, 'J': 0.0027, 'Y': 0.0004, 'X': 0.0003,
    'Q': 0.0002,
}

# Greek (transliterated to Latin) letter frequencies
# Based on modern Greek romanization (standard transliteration A-Z)
# Greek has high A, I, O, E, S, N, T; very low Q, X, W, J
GREEK_FREQ = {
    'A': 0.1150, 'I': 0.0980, 'O': 0.0920, 'E': 0.0880, 'S': 0.0750,
    'N': 0.0720, 'T': 0.0700, 'R': 0.0550, 'P': 0.0450, 'K': 0.0400,
    'L': 0.0380, 'M': 0.0350, 'D': 0.0280, 'G': 0.0200, 'H': 0.0180,
    'U': 0.0170, 'V': 0.0100, 'F': 0.0080, 'C': 0.0060, 'B': 0.0050,
    'Y': 0.0040, 'Z': 0.0030, 'X': 0.0020, 'W': 0.0010, 'J': 0.0005,
    'Q': 0.0005,
}

# French frequencies (another candidate — cryptographic tradition)
FRENCH_FREQ = {
    'E': 0.1210, 'S': 0.0795, 'A': 0.0711, 'I': 0.0694, 'T': 0.0692,
    'N': 0.0686, 'R': 0.0646, 'U': 0.0624, 'L': 0.0545, 'O': 0.0535,
    'D': 0.0367, 'C': 0.0334, 'P': 0.0302, 'M': 0.0297, 'V': 0.0163,
    'Q': 0.0136, 'F': 0.0107, 'B': 0.0090, 'G': 0.0087, 'H': 0.0074,
    'J': 0.0054, 'X': 0.0039, 'Y': 0.0031, 'Z': 0.0014, 'W': 0.0011,
    'K': 0.0005,
}

# Latin frequencies (classical — relevant for inscriptions, CIA motto)
LATIN_FREQ = {
    'I': 0.1128, 'E': 0.1096, 'A': 0.0913, 'U': 0.0856, 'T': 0.0790,
    'S': 0.0734, 'N': 0.0588, 'R': 0.0567, 'O': 0.0527, 'M': 0.0465,
    'C': 0.0421, 'L': 0.0339, 'P': 0.0320, 'D': 0.0312, 'Q': 0.0261,
    'B': 0.0192, 'F': 0.0108, 'G': 0.0107, 'V': 0.0098, 'H': 0.0081,
    'X': 0.0053, 'Y': 0.0009, 'K': 0.0002, 'Z': 0.0001, 'W': 0.0000,
    'J': 0.0000,
}

def build_approx_quadgrams(freq, name):
    """Build approximate quadgram log-probs from monogram frequencies.

    This is a rough approximation (assumes independence), but useful for
    COMPARATIVE scoring across languages. Real quadgrams would be better
    but this lets us test the hypothesis quickly.
    """
    # For comparison purposes, we score as sum of log(freq) for each letter
    # This is effectively a monogram language model, not true quadgrams
    # But it distinguishes languages by their frequency profiles
    log_freq = {}
    for ch, f in freq.items():
        if f > 0:
            log_freq[ch] = math.log10(f)
        else:
            log_freq[ch] = -6.0  # floor for zero-frequency
    return log_freq, name

LANG_MODELS = {}
for name, freq in [('German', GERMAN_FREQ), ('Greek', GREEK_FREQ),
                    ('French', FRENCH_FREQ), ('Latin', LATIN_FREQ)]:
    LANG_MODELS[name] = build_approx_quadgrams(freq, name)

def score_monogram(text, log_freq):
    """Score text using monogram log-frequencies."""
    return sum(log_freq.get(ch, -6.0) for ch in text) / len(text)

def score_english_qg(text):
    """Score with real English quadgrams."""
    if len(text) < 4:
        return QG_EN_FLOOR
    total = sum(QG_EN.get(text[i:i+4], QG_EN_FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)

def ic(text):
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))

# ── Cipher helpers ───────────────────────────────────────────────────────────
def vig_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[c] - ALPH_IDX[key[i % kl]]) % MOD] for i, c in enumerate(ct))

def beau_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[key[i % kl]] - ALPH_IDX[c]) % MOD] for i, c in enumerate(ct))

def varbeau_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[c] + ALPH_IDX[key[i % kl]]) % MOD] for i, c in enumerate(ct))

KEYWORDS = {
    'KRYPTOS': 'KRYPTOS',
    'PALIMPSEST': 'PALIMPSEST',
    'ABSCISSA': 'ABSCISSA',
    'SHADOW': 'SHADOW',
    'SANBORN': 'SANBORN',
    'VERDIGRIS': 'VERDIGRIS',
    'BERLIN': 'BERLIN',
    'URANIA': 'URANIA',       # Greek goddess, connection to KRYPTOS
    'SCHEIDT': 'SCHEIDT',
    'MEDUSA': 'MEDUSA',       # Greek mythology
    'ENIGMA': 'ENIGMA',       # German cipher machine
    'GEHEIM': 'GEHEIM',       # German for "secret"
    'KRYPTOS': 'KRYPTOS',
    'HIDDEN': 'HIDDEN',
}

# German thematic keywords
GERMAN_KEYWORDS = {
    'GEHEIM': 'GEHEIM',           # secret
    'VERBORGEN': 'VERBORGEN',     # hidden
    'SCHATTEN': 'SCHATTEN',       # shadow
    'TUNNEL': 'TUNNEL',           # tunnel (Berlin tunnel)
    'MAUER': 'MAUER',             # wall (Berlin wall)
    'UHRZEIT': 'UHRZEIT',        # clock time
    'WELTZEIT': 'WELTZEIT',       # world time
    'OSTEN': 'OSTEN',             # east
    'NORDEN': 'NORDEN',           # north
    'ALEXANDERPLATZ': 'ALEXANDERPLATZ',  # location of Weltzeituhr
    'FERNSEHTURM': 'FERNSEHTURM',       # TV tower near Weltzeituhr
}

# Greek thematic keywords (transliterated)
GREEK_KEYWORDS = {
    'KRYPTOS': 'KRYPTOS',         # hidden (Greek)
    'OURANIA': 'OURANIA',         # Urania (muse of astronomy)
    'ALETHEIA': 'ALETHEIA',       # truth
    'SOPHIA': 'SOPHIA',           # wisdom
    'ENIGMA': 'ENIGMA',           # riddle
    'MYSTIKOS': 'MYSTIKOS',       # mystic/secret
    'KRYPTE': 'KRYPTE',           # crypt/hidden place
    'APOKRYPHOS': 'APOKRYPHOS',   # apocryphal/hidden
    'LOGOS': 'LOGOS',             # word/reason
    'NOUS': 'NOUS',               # mind/intellect
}

DECRYPTORS = {
    'Vig': vig_decrypt,
    'Beau': beau_decrypt,
    'VBeau': varbeau_decrypt,
}

# ── Reference: known language ICs ────────────────────────────────────────────
LANG_IC = {
    'English': 0.0667, 'German': 0.0762, 'French': 0.0778,
    'Italian': 0.0738, 'Spanish': 0.0775, 'Greek': 0.0660,
    'Latin': 0.0770, 'Random': 0.0385,
}

print("=" * 70)
print("MULTILINGUAL K4 DECRYPTION TEST")
print("  Hypothesis: K4 plaintext may contain non-English text")
print("  Testing: German, Greek, French, Latin scoring")
print("=" * 70)

# ── Phase 1: Score raw K4 CT against each language model ─────────────────────
print("\n--- Phase 1: Raw K4 frequency profile ---")
print(f"  K4 IC = {ic(CT):.4f}")
print(f"  Reference ICs: {LANG_IC}")
ct_freq = Counter(CT)
print(f"  K4 top-5 letters: {ct_freq.most_common(5)}")
for lang_name, (log_freq, _) in LANG_MODELS.items():
    s = score_monogram(CT, log_freq)
    print(f"  Raw CT vs {lang_name}: {s:.4f}")

# ── Phase 2: Decrypt with all combos, score each language ────────────────────
print("\n--- Phase 2: Decrypt and score across languages ---")

all_keywords = {}
all_keywords.update(KEYWORDS)
all_keywords.update(GERMAN_KEYWORDS)
all_keywords.update(GREEK_KEYWORDS)

# Track best per language
best_per_lang = {lang: (-999, '', '') for lang in list(LANG_MODELS.keys()) + ['English']}
results = []

for kname, key in all_keywords.items():
    for dname, decrypt in DECRYPTORS.items():
        pt = decrypt(CT, key)

        # Score against each language
        scores = {}
        scores['English'] = score_english_qg(pt)
        for lang_name, (log_freq, _) in LANG_MODELS.items():
            scores[lang_name] = score_monogram(pt, log_freq)

        pt_ic = ic(pt)

        # Find which language scores best (normalize: monogram scores are
        # on different scale than quadgrams, so compare within each language)
        for lang, s in scores.items():
            if s > best_per_lang[lang][0]:
                best_per_lang[lang] = (s, pt, f"{dname}/{kname}")

        # Record interesting results
        best_lang = max(scores, key=scores.get)
        if best_lang != 'English' or scores['English'] > -6.0:
            results.append({
                'method': f"{dname}/{kname}",
                'pt': pt[:60],
                'ic': pt_ic,
                'scores': scores,
                'best_lang': best_lang,
            })

# ── Phase 3: Results ─────────────────────────────────────────────────────────
print("\n--- Phase 3: Best decryption per language ---")
for lang in ['English', 'German', 'Greek', 'French', 'Latin']:
    score, pt, method = best_per_lang[lang]
    print(f"\n  {lang}: score={score:.4f} via {method}")
    print(f"    PT: {pt[:70]}")
    print(f"    IC: {ic(pt):.4f}")

# ── Phase 4: German-specific deep test ───────────────────────────────────────
print("\n" + "=" * 70)
print("Phase 4: German-specific analysis")
print("  Testing German cribs: OSTNORDOST, BERLINUHR, WELTZEITUHR")
print("=" * 70)

GERMAN_CRIBS = ['OSTNORDOST', 'BERLINUHR', 'WELTZEITUHR', 'GEHEIM', 'TUNNEL',
                'SCHATTEN', 'MAUER', 'OSTEN', 'NORDEN', 'UNTERGRUND',
                'VERBORGENSCHATZ', 'WUNDERBAR']

for kname, key in all_keywords.items():
    for dname, decrypt in DECRYPTORS.items():
        pt = decrypt(CT, key)
        for crib in GERMAN_CRIBS:
            if crib in pt:
                print(f"  *** GERMAN CRIB HIT: '{crib}' in {dname}/{kname}")
                print(f"      PT: {pt}")
                print(f"      Position: {pt.index(crib)}")

# ── Phase 5: Greek-specific deep test ────────────────────────────────────────
print("\n" + "=" * 70)
print("Phase 5: Greek (transliterated) crib search")
print("=" * 70)

GREEK_CRIBS = ['KRYPTOS', 'OURANIA', 'ALETHEIA', 'SOPHIA', 'MYSTIKOS',
               'KRYPTE', 'APOKRYPHOS', 'LOGOS', 'NOUS', 'THEOS',
               'KOSMOS', 'PSYCHE', 'GNOSIS', 'AGAPE', 'ELPIS',
               'ARETE', 'HUBRIS', 'KAIROS', 'TELOS', 'OIKOS',
               'POLIS', 'DEMOS', 'KRATOS', 'ARCHON', 'DAEMON']

for kname, key in all_keywords.items():
    for dname, decrypt in DECRYPTORS.items():
        pt = decrypt(CT, key)
        for crib in GREEK_CRIBS:
            if crib in pt:
                print(f"  *** GREEK CRIB HIT: '{crib}' in {dname}/{kname}")
                print(f"      PT: {pt}")
                print(f"      Position: {pt.index(crib)}")

# ── Phase 6: IC analysis — what language matches K4's encrypted IC? ──────────
print("\n" + "=" * 70)
print("Phase 6: IC-based language discrimination")
print("  K4 IC = 0.0361. What source language + key period produces this?")
print("=" * 70)

# For Vigenère with period p, expected IC ≈ (1/p)*IC_lang + (1-1/p)*IC_random
for lang, ic_lang in LANG_IC.items():
    if lang == 'Random':
        continue
    for period in [7, 8, 10, 13]:
        expected_ic = (1.0/period) * ic_lang + (1.0 - 1.0/period) * (1.0/26)
        print(f"  {lang:8s} period={period:2d}: expected IC = {expected_ic:.4f}"
              f"  (K4={ic(CT):.4f}, delta={abs(expected_ic - ic(CT)):.4f})")

# ── Phase 7: Free crib search with German/Greek words ────────────────────────
print("\n" + "=" * 70)
print("Phase 7: Extended free crib search (all languages)")
print("=" * 70)

ALL_CRIBS = (['EASTNORTHEAST', 'BERLINCLOCK'] + GERMAN_CRIBS + GREEK_CRIBS +
             ['PALIMPSEST', 'ABSCISSA', 'SHADOW', 'KRYPTOS', 'VERDIGRIS',
              'LAYER', 'POSITION', 'BETWEEN', 'SUBTLE', 'SHADING',
              'ABSENCE', 'LIGHT', 'NUANCE', 'ILLUSION',
              'DESPERATE', 'SLOWLY', 'REMAINS', 'BURIED',
              'TOTALLY', 'INVISIBLE', 'HIDDEN'])

hit_count = 0
for kname, key in all_keywords.items():
    for dname, decrypt in DECRYPTORS.items():
        pt = decrypt(CT, key)
        for crib in ALL_CRIBS:
            if len(crib) >= 5 and crib in pt:
                hit_count += 1
                print(f"  HIT: '{crib}' at pos {pt.index(crib)} in {dname}/{kname}")
                print(f"    PT: {pt}")

if hit_count == 0:
    print("  No crib hits in any language.")

print(f"\nTotal configs tested: {len(all_keywords) * len(DECRYPTORS)}")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)
