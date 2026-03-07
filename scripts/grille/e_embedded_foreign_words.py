#!/usr/bin/env python3
"""
Search for embedded Greek/German words in K4 plaintext at non-crib positions.

We know 24 crib characters (EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73).
The remaining 73 positions are unknown. For each keyword + cipher variant,
we can derive what the plaintext WOULD be at every position. Then search
those derived plaintexts for Greek and German words.

Cipher: Vigenere/Beaufort/VarBeau
Family: grille
Status: active
"""
import sys, os, json
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

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

# ── Load English quadgrams for comparison ────────────────────────────────────
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    QG_EN = json.load(f)
QG_EN_FLOOR = min(QG_EN.values()) - 1.0

def qg_score(text):
    if len(text) < 4:
        return QG_EN_FLOOR
    total = sum(QG_EN.get(text[i:i+4], QG_EN_FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)

# ── Greek words (transliterated) — thematic for Kryptos ─────────────────────
# Focus on words that could plausibly appear in a CIA/espionage/archaeology context
GREEK_WORDS = [
    # Direct Kryptos connections
    'KRYPTOS', 'KRYPTE', 'KRYPTON', 'KRYPTEIA',
    'APOKRYPHOS', 'APOKRYPHA',
    # Truth/knowledge
    'ALETHEIA', 'ALETHES', 'GNOSIS', 'EPISTEME', 'SOPHIA', 'LOGOS',
    'NOUS', 'NOESIS', 'THEORIA',
    # Mythology/culture
    'OURANIA', 'URANIA', 'HERMES', 'ATHENA', 'APOLLO', 'DELPHI',
    'ORACLE', 'SPHINX', 'ENIGMA', 'MYSTERION', 'MYSTIKOS',
    'PSYCHE', 'DAEMON', 'THEOS', 'KOSMOS', 'CHAOS',
    'ARETE', 'HUBRIS', 'NEMESIS', 'KAIROS', 'CHRONOS',
    'TELOS', 'ARCHON', 'KRATOS', 'POLIS', 'AGORA',
    # Directional/positional (matching K4 themes)
    'ANATOLI', 'VOREIO', 'VOREIA', 'DYTIKO', 'NOTIO',
    # Hiding/secret
    'KRYPHO', 'KEKRYMMENON', 'MYSTIKON', 'APHANTOS',
    'PHANTASMA', 'EIDOLON', 'SKIA',  # shadow
    # Archaeology (K3 = Carter tomb)
    'THOLOS', 'STELE', 'STELAE',
    'SARKO', 'SARKOPHAGOS',
    'NECROPOLIS', 'NEKROPOLIS',
    'PHAROS', 'PIRAMIS',
    # Philosophy
    'PRAGMA', 'PRAXIS', 'POIESIS', 'TECHNE', 'ERGON',
    'AION', 'ANANKE', 'MOIRA', 'TYCHE',
    # Short but distinctive
    'ZOE', 'BIOS', 'PHOS', 'NEOS', 'PALEO',
    'ARCHE', 'ALPHA', 'OMEGA', 'DELTA', 'SIGMA', 'GAMMA',
    'IOTA', 'KAPPA', 'LAMBDA', 'THETA', 'EPSILON',
    'PATHOS', 'ETHOS', 'MYTHOS',
]

# ── German words — thematic for Berlin/espionage/Kryptos ─────────────────────
GERMAN_WORDS = [
    # Espionage/intelligence
    'GEHEIM', 'GEHEIMNIS', 'GEHEIMDIENST',
    'SPION', 'SPIONAGE', 'AGENT', 'AGENTEN',
    'NACHRICHT', 'NACHRICHTEN', 'BOTSCHAFT',
    'VERSCHLUSS', 'VERSCHLUESSELUNG',
    'ENTSCHLUESSELUNG', 'CHIFFRE', 'CHIFFRIERT',
    'VERBOTEN', 'VERBORGEN', 'VERSTECKT',
    'TARNUNG', 'TARNNAME',
    'FEIND', 'FEINDE',
    # Berlin/Cold War
    'BERLIN', 'MAUER', 'MAUERN',
    'TUNNEL', 'TUNNELS',
    'OSTEN', 'WESTEN', 'NORDEN', 'SUEDEN',
    'OSTNORDOST',
    'GRENZE', 'GRENZEN',
    'FLUCHT', 'FREIHEIT',
    'STASI', 'KREML',
    'ALEXANDERPLATZ', 'FERNSEHTURM',
    'BRANDENBURGERTOR',
    'CHECKPOINT',
    # Time/clock (Weltzeituhr)
    'UHRZEIT', 'WELTZEIT', 'WELTUHR', 'WELTZEITUHR',
    'STUNDE', 'STUNDEN', 'MITTERNACHT',
    'ZEIT', 'ZEITEN',
    # Shadow/light (Kryptos themes)
    'SCHATTEN', 'LICHT', 'DUNKEL', 'DUNKELHEIT',
    'ZWISCHEN', 'NUANCE',
    'SCHATTIERUNG', 'ABWESENHEIT',
    'ILLUSION', 'TAEUSCHUNG',
    # Hidden/secret
    'RAETSEL', 'GEHEIMSCHRIFT',
    'SCHLUESSEL', 'SCHLUSSEL',
    'UNSICHTBAR', 'SICHTBAR',
    'WAHRHEIT', 'LUEGE',
    # Archaeology (K3 tomb theme)
    'GRAB', 'GRABMAL', 'GRABKAMMER',
    'SCHATZ', 'SCHAETZE',
    'ENTDECKUNG', 'ENTDECKT',
    'WUNDERBAR', 'HERRLICH',
    'PHARAO', 'PYRAMIDE',
    'GOLD', 'GOLDEN',
    # Architecture/art (Sanborn themes)
    'SKULPTUR', 'KUPFER', 'PATINA',
    'GRUENSPAN',  # = verdigris in German!
    'INSCHRIFT', 'GRAVUR',
    'KUNST', 'KUENSTLER',
    # Short but distinctive
    'NACHT', 'TAG', 'STEIN', 'WASSER',
    'FEUER', 'ERDE', 'LUFT', 'WIND',
    'KRIEG', 'FRIEDE', 'FRIEDEN',
    'MACHT', 'KRAFT',
    'RECHT', 'PFLICHT',
    'TOD', 'LEBEN',
    'ENDE', 'ANFANG',
    'HIER', 'DORT',
    'NICHTS', 'ALLES',
    'WAHR', 'FALSCH',
    'UNTER', 'GRUND', 'UNTERGRUND',
]

# ── Additional English thematic words we haven't tested as embedded ──────────
ENGLISH_THEMATIC = [
    'KRYPTOS', 'HIDDEN', 'SECRET', 'SHADOW', 'POSITION',
    'BETWEEN', 'SUBTLE', 'SHADING', 'ABSENCE', 'LIGHT',
    'INVISIBLE', 'BURIED', 'UNDERGROUND', 'TRANSMITTED',
    'UNKNOWN', 'LOCATION', 'DESPERATE', 'SLOWLY',
    'WONDERFUL', 'THINGS', 'TREASURE', 'DISCOVERY',
    'CHAMBER', 'TOMB', 'ANCIENT', 'CIPHER',
    'MATRIX', 'LAYER', 'TABLEAU', 'GRILLE',
    'VERDIGRIS', 'PATINA', 'COPPER', 'SCULPTURE',
    'LANGLEY', 'AGENCY', 'CENTRAL', 'INTELLIGENCE',
    'SCHEIDT', 'SANBORN',
    'COMPASS', 'LODESTONE', 'MAGNETIC',
    'CLOCK', 'WELTZEITUHR',
    'PALIMPSEST', 'ABSCISSA',
]

KEYWORDS = {
    'KRYPTOS': 'KRYPTOS',
    'PALIMPSEST': 'PALIMPSEST',
    'ABSCISSA': 'ABSCISSA',
    'SHADOW': 'SHADOW',
    'SANBORN': 'SANBORN',
    'VERDIGRIS': 'VERDIGRIS',
    'BERLIN': 'BERLIN',
    'URANIA': 'URANIA',
    'SCHEIDT': 'SCHEIDT',
    'GEHEIM': 'GEHEIM',
    'ENIGMA': 'ENIGMA',
    'KRYPTE': 'KRYPTE',
    'ALETHEIA': 'ALETHEIA',
    'MEDUSA': 'MEDUSA',
    'HIDDEN': 'HIDDEN',
    'SECRET': 'SECRET',
    'PATINA': 'PATINA',
    'GRUENSPAN': 'GRUENSPAN',  # verdigris in German
}

DECRYPTORS = {
    'Vig': vig_decrypt,
    'Beau': beau_decrypt,
    'VBeau': varbeau_decrypt,
}

# Combine all search words, filter to length >= 4
ALL_SEARCH = set()
for w in GREEK_WORDS + GERMAN_WORDS + ENGLISH_THEMATIC:
    if len(w) >= 4:
        ALL_SEARCH.add(w.upper())

print("=" * 70)
print("EMBEDDED FOREIGN WORD SEARCH IN K4 PLAINTEXT")
print(f"  Search words: {len(ALL_SEARCH)} (Greek + German + English thematic)")
print(f"  Keywords: {len(KEYWORDS)}")
print(f"  Decryptors: {len(DECRYPTORS)}")
print(f"  Total configs: {len(KEYWORDS) * len(DECRYPTORS)}")
print("=" * 70)

# ── Check crib consistency first ─────────────────────────────────────────────
print("\n--- Crib-consistent configurations ---")
consistent = []
for kname, key in KEYWORDS.items():
    kl = len(key)
    for dname, decrypt in DECRYPTORS.items():
        pt = decrypt(CT, key)
        # Check how many crib positions match
        matches = sum(1 for pos, ch in CRIB_DICT.items() if pt[pos] == ch)
        if matches >= 3:
            consistent.append((matches, kname, dname, pt))

consistent.sort(reverse=True)
print(f"  {len(consistent)} configs with >= 3 crib matches")
for matches, kname, dname, pt in consistent[:10]:
    print(f"  [{matches:2d}/24] {dname}/{kname}: {pt[:70]}")

# ── Main search ──────────────────────────────────────────────────────────────
print("\n--- Searching for embedded words ---")

hits = []
for kname, key in KEYWORDS.items():
    for dname, decrypt in DECRYPTORS.items():
        pt = decrypt(CT, key)
        for word in ALL_SEARCH:
            pos = pt.find(word)
            if pos >= 0:
                # Determine if this overlaps with crib positions
                word_positions = set(range(pos, pos + len(word)))
                crib_positions = set(CRIB_DICT.keys())
                overlap = word_positions & crib_positions
                non_crib = len(word_positions - crib_positions)

                # Determine language
                lang = 'EN'
                if word in [w.upper() for w in GERMAN_WORDS]:
                    lang = 'DE'
                elif word in [w.upper() for w in GREEK_WORDS]:
                    lang = 'GR'

                hits.append({
                    'word': word,
                    'lang': lang,
                    'pos': pos,
                    'len': len(word),
                    'method': f"{dname}/{kname}",
                    'overlap_crib': len(overlap),
                    'non_crib_chars': non_crib,
                    'pt': pt,
                    'qg': qg_score(pt),
                })

# Sort: prefer longer words, then fewer crib overlaps (more surprising)
hits.sort(key=lambda h: (-h['len'], h['overlap_crib'], -h['non_crib_chars']))

# Deduplicate: same word at same position
seen = set()
unique_hits = []
for h in hits:
    key = (h['word'], h['pos'], h['method'])
    if key not in seen:
        seen.add(key)
        unique_hits.append(h)

print(f"\n  Total hits: {len(unique_hits)}")

if unique_hits:
    # Group by language
    by_lang = defaultdict(list)
    for h in unique_hits:
        by_lang[h['lang']].append(h)

    for lang_code, lang_name in [('GR', 'GREEK'), ('DE', 'GERMAN'), ('EN', 'ENGLISH')]:
        lang_hits = by_lang.get(lang_code, [])
        if not lang_hits:
            print(f"\n  {lang_name}: No hits")
            continue

        print(f"\n  {lang_name}: {len(lang_hits)} hits")
        # Show top hits (longest words, least crib overlap)
        for h in lang_hits[:25]:
            crib_note = f" (crib overlap: {h['overlap_crib']})" if h['overlap_crib'] > 0 else ""
            print(f"    '{h['word']}' [{h['lang']}] at pos {h['pos']:2d} "
                  f"via {h['method']:20s} qg={h['qg']:.3f}{crib_note}")
            # Show context: 5 chars before and after
            start = max(0, h['pos'] - 5)
            end = min(97, h['pos'] + h['len'] + 5)
            context = h['pt'][start:end]
            word_start = h['pos'] - start
            word_end = word_start + h['len']
            highlighted = context[:word_start] + '[' + context[word_start:word_end] + ']' + context[word_end:]
            print(f"      ...{highlighted}...")

    # ── Interesting patterns: same word appears with multiple keys ────────
    print("\n--- Words appearing with multiple key/cipher combos ---")
    word_methods = defaultdict(list)
    for h in unique_hits:
        word_methods[h['word']].append(h['method'])

    multi = {w: ms for w, ms in word_methods.items() if len(ms) >= 2}
    if multi:
        for word, methods in sorted(multi.items(), key=lambda x: -len(x[1])):
            print(f"  '{word}': appears in {len(methods)} configs")
    else:
        print("  None — each word appears in only one config")

    # ── Highlight: words that appear OUTSIDE crib regions ────────────────
    print("\n--- Words entirely outside crib positions (most interesting) ---")
    non_crib_hits = [h for h in unique_hits if h['overlap_crib'] == 0 and h['len'] >= 5]
    if non_crib_hits:
        for h in non_crib_hits[:20]:
            print(f"  '{h['word']}' [{h['lang']}] at pos {h['pos']:2d} "
                  f"via {h['method']:20s} qg={h['qg']:.3f}")
            start = max(0, h['pos'] - 5)
            end = min(97, h['pos'] + h['len'] + 5)
            context = h['pt'][start:end]
            word_start = h['pos'] - start
            word_end = word_start + h['len']
            highlighted = context[:word_start] + '[' + context[word_start:word_end] + ']' + context[word_end:]
            print(f"      ...{highlighted}...")
    else:
        print("  None with length >= 5 entirely outside cribs")

else:
    print("  No embedded words found in any configuration.")

# ── Phase 2: Try with KA alphabet ───────────────────────────────────────────
print("\n" + "=" * 70)
print("Phase 2: Same search with KA alphabet (KRYPTOSABCDEFGHIJLMNQUVWXZ)")
print("=" * 70)

KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_IDX = {c: i for i, c in enumerate(KA)}

def vig_decrypt_ka(ct, key):
    kl = len(key)
    return ''.join(KA[(KA_IDX[c] - KA_IDX[key[i % kl]]) % 26] for i, c in enumerate(ct))

def beau_decrypt_ka(ct, key):
    kl = len(key)
    return ''.join(KA[(KA_IDX[key[i % kl]] - KA_IDX[c]) % 26] for i, c in enumerate(ct))

KA_DECRYPTORS = {'Vig/KA': vig_decrypt_ka, 'Beau/KA': beau_decrypt_ka}

ka_hits = []
for kname, key in KEYWORDS.items():
    for dname, decrypt in KA_DECRYPTORS.items():
        pt = decrypt(CT, key)
        for word in ALL_SEARCH:
            pos = pt.find(word)
            if pos >= 0:
                word_positions = set(range(pos, pos + len(word)))
                crib_positions = set(CRIB_DICT.keys())
                overlap = word_positions & crib_positions

                lang = 'EN'
                if word in [w.upper() for w in GERMAN_WORDS]:
                    lang = 'DE'
                elif word in [w.upper() for w in GREEK_WORDS]:
                    lang = 'GR'

                ka_hits.append({
                    'word': word,
                    'lang': lang,
                    'pos': pos,
                    'len': len(word),
                    'method': f"{dname}/{kname}",
                    'overlap_crib': len(overlap),
                    'pt': pt,
                })

seen2 = set()
unique_ka = []
for h in ka_hits:
    key2 = (h['word'], h['pos'], h['method'])
    if key2 not in seen2:
        seen2.add(key2)
        unique_ka.append(h)

unique_ka.sort(key=lambda h: (-h['len'], h['overlap_crib']))

print(f"  KA-alphabet hits: {len(unique_ka)}")
for h in unique_ka[:20]:
    crib_note = f" (crib overlap: {h['overlap_crib']})" if h['overlap_crib'] > 0 else ""
    print(f"  '{h['word']}' [{h['lang']}] at pos {h['pos']:2d} via {h['method']:20s}{crib_note}")
    start = max(0, h['pos'] - 5)
    end = min(97, h['pos'] + h['len'] + 5)
    context = h['pt'][start:end]
    word_start = h['pos'] - start
    word_end = word_start + h['len']
    highlighted = context[:word_start] + '[' + context[word_start:word_end] + ']' + context[word_end:]
    print(f"      ...{highlighted}...")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)
