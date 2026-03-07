#!/usr/bin/env python3
"""
Bean-Keyword Constructor Plausibility Filter
=============================================
Cipher:   polyalphabetic (Vigenère / Beaufort)
Family:   grille
Status:   active
Keyspace: 5,206 Bean-passing words → plausibility filter → ranked output
Last run: never
Best score: n/a

Takes the Bean-passing word list from e_bean_keyword_filter.py and applies
aggressive constructor-plausibility filtering per Sanborn's known aesthetic.

Usage:
    PYTHONPATH=src python3 -u scripts/grille/e_bean_plausibility_filter.py
"""
import csv
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

# ── Load Bean-passing words with glosses from the ranked TSV ─────────────

def load_bean_words(tsv_path: str) -> list[dict]:
    """Load Bean-passing words from the ranked TSV."""
    words = []
    with open(tsv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            words.append({
                'word': row['word'],
                'length': int(row['length']),
                'pos': row['pos'],
                'raw_theme': int(row['theme_score']),
                'eq_pos': row['eq_positions'],
                'gloss': row.get('gloss', ''),
                'categories': row.get('categories', ''),
            })
    return words


# ═══════════════════════════════════════════════════════════════════════════
# FILTERING FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════

# ── Structural parameters ────────────────────────────────────────────────
PREFERRED_LEN_MIN = 5
PREFERRED_LEN_MAX = 13
HARD_LEN_MAX = 20  # absolute ceiling
ACCEPTABLE_POS = {'noun', 'adj', 'verb', 'name'}
PREFERRED_POS = {'noun', 'adj'}  # Sanborn's keywords are almost all nouns

# ── HARD REJECT rules ────────────────────────────────────────────────────

# Derivational suffix chains that signal jargon, not intentional keywords
HARD_REJECT_SUFFIXES = re.compile(
    r'(?:'
    r'ization$|izations$|ationaliz|ationally$|istically$|'
    r'ologically$|iveness$|ibilities$|nesses$|fulness$|'
    r'ousness$|ability$|ibility$|'
    r'ified$|ifiers$|izations$|'
    r'istically$|ionality$'
    r')', re.I
)

# Biomedical / chemical / taxonomic — applied to WORD only
# Careful: avoid matching common words (MAGAZINE, DECEPTOR, MONOXIDE, etc.)
BIOMEDICAL_WORD = re.compile(
    r'(?:'
    r'ectomy$|oscopy$|itis$|emia$|uria$|algia$|pathy$|'
    r'plasty$|sclerosis$|'
    r'aceae$|idae$|inae$|oidea$|phyte$|cyte$|blast$|'
    r'azole$|ylene$|ethyl|methyl|'
    r'kinase$|lipase$|'
    r'glucos|fructos|peptid|nucleotid|ribosom'
    r')', re.I
)

# Words that falsely match biomedical patterns but are common/thematic
BIOMEDICAL_EXEMPT = {
    'MAGAZINE', 'DECEPTOR', 'RECEPTOR', 'MONOPOLE', 'MONOXIDE',
    'CEREMENT', 'PARADISE', 'PARASITE', 'CEREMONY', 'MINISTER',
    'MONOLITH', 'MACARONI', 'PALATINE', 'EPIPHANY', 'DIVINITY',
}

# Mineralogy -ite pattern (applied to WORD + requires mineral-like gloss)
MINERAL_SUFFIX = re.compile(r'(?:ite|ite[s])$', re.I)
MINERAL_GLOSS = re.compile(
    r'(?i)\b(mineral|chemical formula|crystal|monoclinic|triclinic|'
    r'orthorhombic|isometric|hexagonal|tetragonal|sulfide|silicate|'
    r'phosphate|carbonate|arsenate|fluoride|chloride|hydroxide)\b'
)

# Adverbs ending in -ly: only reject if POS is 'adv'
# (MONOPOLY, ANOMALY, etc. are nouns ending in -ly, don't reject those)

# Sports / cooking / fashion / internet / business jargon (gloss-based)
# Note: "garment" removed — too broad (catches burial shrouds like CEREMENT)
DOMAIN_REJECT_GLOSS = re.compile(
    r'(?i)\b('
    r'baseball|football|basketball|soccer|cricket|tennis|golf|hockey|'
    r'skiing|skating|surfing|wrestling|boxing|'
    r'recipe|cooking|culinary|cuisine|baking|'
    r'fashion\b|textile|dressmaking|'
    r'internet|website|software|app\b|startup|'
    r'accounting|bookkeeping|invoicing|'
    r'dentistry|orthodontic|endoscop|'
    r'pokemon|anime|manga|video game'
    r')\b'
)

# Reject gerunds and present participles used as nouns when base verb is common
GERUND_ING = re.compile(r'^.{5,}ing$', re.I)
# But allow: CROSSING, BEARING, BUILDING, CARVING, ENGRAVING, etc.
GERUND_EXCEPTIONS = {
    'CROSSING', 'BEARING', 'BUILDING', 'CARVING', 'ENGRAVING',
    'OFFERING', 'BLESSING', 'DWELLING', 'ETCHING', 'HEADING',
    'DRAFTING', 'SHIELDING', 'SHADING', 'ENCODING', 'DECODING',
    'LIGHTING', 'FLOORING', 'GROUNDING', 'FOUNDING', 'CASTING',
    'MOUNTING', 'VAULTING', 'CHARTING', 'MAPPING', 'TRACKING',
    'SOUNDING', 'SIGHTING', 'MOORING', 'RIGGING', 'PLUMBING',
    'LODGING', 'TOOLING', 'FRAMING', 'MOULDING', 'MOLDING',
    'RECKONING', 'CLADDING', 'COUPLING', 'BRIDGING', 'SPANNING',
}


def hard_reject(word: str, pos: str, gloss: str) -> str | None:
    """Return rejection reason or None if word passes."""
    w = word.upper()
    L = len(w)

    # Absolute length limits
    if L > HARD_LEN_MAX:
        return f"too long ({L})"
    if L < 3:
        return "too short"

    # Derivational jargon suffixes
    if HARD_REJECT_SUFFIXES.search(w):
        return "derivational suffix chain"

    # Biomedical / chemical (word pattern, with exemptions)
    if w not in BIOMEDICAL_EXEMPT and BIOMEDICAL_WORD.search(w):
        return "biomedical/chemical"

    # Mineralogy: -ite suffix + mineral-like gloss = reject
    if MINERAL_SUFFIX.search(w) and MINERAL_GLOSS.search(gloss):
        return "mineralogy"

    # Adverb -ly: only reject actual adverbs (not nouns like MONOPOLY, ANOMALY)
    if pos == 'adv' and L >= 6 and w.endswith('LY'):
        return "adverb -ly"

    # Domain rejection by gloss
    if DOMAIN_REJECT_GLOSS.search(gloss):
        return "rejected domain (sports/cooking/fashion/internet)"

    # POS-based rejection
    if pos in ('suffix', 'prefix', 'infix', 'affix', 'character', 'symbol',
               'punct', 'particle'):
        return f"POS: {pos}"

    return None


# ── SOFT PENALTY rules ───────────────────────────────────────────────────

def soft_penalties(word: str, pos: str, gloss: str) -> list[tuple[str, float]]:
    """Return list of (reason, penalty) pairs."""
    penalties = []
    w = word.upper()
    L = len(w)

    # Morphological complexity
    if L > 13:
        penalties.append(("long word", -1.0))
    if L > 16:
        penalties.append(("very long word", -1.5))

    # Gerunds (except thematic exceptions)
    if GERUND_ING.match(w) and w not in GERUND_EXCEPTIONS:
        penalties.append(("gerund/participle -ing", -0.5))

    # Past tense forms
    if re.search(r'(?:ated|eted|ited|uted|ened|oned|ized|ised)$', w, re.I):
        penalties.append(("past tense/participial", -0.5))

    # Inflected plurals
    if re.search(r'(?:ies|ches|shes|xes)$', w, re.I):
        penalties.append(("inflected plural", -0.5))

    # Non-noun/adj POS
    if pos == 'verb':
        penalties.append(("verb (less likely as keyword)", -0.5))
    elif pos == 'adv':
        penalties.append(("adverb", -1.0))
    elif pos == 'name':
        penalties.append(("proper noun (possible but less likely)", -0.3))
    elif pos in ('det', 'prep', 'conj', 'pron', 'intj', 'num'):
        penalties.append((f"function word ({pos})", -2.0))

    # Modern jargon unlikely in 1990
    if re.search(r'(?i)\b(internet|digital|cyber|online|email|blog|'
                 r'smartphone|laptop|selfie|hashtag|podcast|streaming|'
                 r'cryptocurrency|blockchain|crowdfund)\b', gloss):
        penalties.append(("modern jargon (post-1990)", -2.0))

    # Weak imagery
    if re.search(r'(?i)\b(abstract concept|philosophical term|rare|obsolete)\b', gloss):
        penalties.append(("weak imagery/obsolete", -0.3))

    return penalties


# ═══════════════════════════════════════════════════════════════════════════
# CONSTRUCTOR PLAUSIBILITY SCORING
# ═══════════════════════════════════════════════════════════════════════════

# Sanborn's conceptual universe - scored by domain

DOMAIN_SCORES = {
    'cryptography_secrecy': {
        'words': {
            'CIPHER', 'SECRET', 'ENCRYPT', 'DECRYPT', 'CONCEAL', 'REVEAL',
            'ENIGMA', 'MYSTERY', 'PUZZLE', 'RIDDLE', 'ARCANE', 'ESOTERIC',
            'OCCULT', 'INVISIBLE', 'UNSEEN', 'COVERT', 'HIDDEN', 'SHROUD',
            'VEIL', 'MASK', 'CLOAK', 'OBSCURE', 'PHANTOM', 'SPECTER',
            'SPECTRE', 'ILLUSION', 'MIRAGE', 'DECEPTION', 'DISGUISE',
            'PARADOX', 'APERTURE', 'SENTINEL', 'GUARDIAN', 'WATCHMAN',
            'SUBTLETY', 'ARTIFICE', 'PALIMPSEST', 'STEGANOGRAPHY',
        },
        'roots': ['crypt', 'cipher', 'secret', 'hidden', 'covert', 'conceal',
                  'enigma', 'occult', 'arcane', 'esoteric', 'grille', 'cardan',
                  'vigen', 'beaufort', 'encipher', 'decipher', 'scrambl',
                  'palimps', 'stegano'],
        'weight': 5,
    },
    'cold_war_berlin': {
        'words': {
            'ESPIONAGE', 'FRONTIER', 'CURTAIN', 'DEFECTOR', 'TURNCOAT',
            'DEFECTION', 'DIPLOMAT', 'EMBASSY', 'ATTACHE', 'INTRIGUE',
            'FUGITIVE', 'PASSPORT', 'GARRISON', 'BLOCKADE', 'CORRIDOR',
            'INFORMER', 'SABOTAGE', 'SUBVERT', 'PARTISAN', 'EMISSARY',
            'DISPATCH', 'COMMUNIQUE', 'DOSSIER', 'ARCHIVE', 'PROTOCOL',
            'EXFILTRATE', 'SPYPLANE', 'INFORMANT', 'OPERATIVE', 'HANDLER',
            'SAFEHOUSE', 'DEBRIEFING', 'TRADECRAFT', 'DEAD DROP',
        },
        'roots': ['spy', 'espionag', 'berlin', 'surveil', 'intel',
                  'frontier', 'border', 'curtain', 'infiltr', 'defect',
                  'embassy', 'garrison', 'blockad', 'sabotag', 'subver',
                  'partisan', 'dispatch', 'dossier', 'archiv', 'protocol',
                  'exfiltr', 'informan', 'operativ', 'handler', 'safehouse',
                  'debrief', 'tradecra', 'rendezvo', 'clandestin', 'fugitiv'],
        'weight': 5,  # boosted: K4 cribs reference EAST NORTH EAST + BERLIN CLOCK
    },
    'geometry_coordinates': {
        'words': {
            'ABSCISSA', 'ORDINATE', 'AZIMUTH', 'MERIDIAN', 'QUADRANT',
            'PARALLAX', 'TANGENT', 'BISECTOR', 'SYMMETRY', 'ROTATION',
            'PARABOLA', 'ELLIPSE', 'TRAVERSE', 'GEODESIC', 'TOPOLOGY',
            'MANIFOLD', 'GRADIENT', 'LATITUDE', 'POLARITY', 'INVERSION',
        },
        'roots': ['absciss', 'ordinat', 'azimuth', 'meridian', 'quadrant',
                  'parallax', 'tangent', 'symmetr', 'rotat', 'geodesic',
                  'topolog', 'manifold', 'gradient', 'latitud', 'longitud',
                  'permut', 'matrix', 'vector', 'coordin', 'triangul'],
        'weight': 5,
    },
    'time_light_shadow': {
        'words': {
            'SOLSTICE', 'EQUINOX', 'ECLIPTIC', 'PENUMBRA', 'GNOMON',
            'TWILIGHT', 'MIDNIGHT', 'HORIZON', 'ZENITH', 'NADIR',
            'SPECTRUM', 'RADIANCE', 'APERTURE', 'LUMINOUS', 'NOCTURNE',
            'DIURNAL', 'CARDINAL', 'CELESTIAL', 'CREPUSCLE', 'LANTERN',
            'HOROLOGE', 'HOROLOGY', 'TIMEPIECE', 'CHRONOMETER',
        },
        'roots': ['eclipse', 'equinox', 'solstice', 'penumbra', 'gnomon',
                  'sundial', 'shadow', 'twilight', 'horizon', 'zenith',
                  'nadir', 'spectrum', 'radianc', 'luminous', 'noctur',
                  'diurnal', 'celestial', 'cardinal', 'lantern', 'apertur',
                  'horolog', 'chronom', 'timepiece', 'clock', 'dial'],
        'weight': 4,
    },
    'water_reflection': {
        'words': {
            'FOUNTAIN', 'CASCADE', 'CURRENT', 'UNDULATE', 'AQUIFER',
            'AQUEDUCT', 'CONDUIT', 'WELLSPRING', 'CISTERN', 'TORRENT',
            'MAELSTROM', 'EDDY', 'CONFLUENCE',
        },
        'roots': ['fountain', 'cascade', 'current', 'undulat', 'aquifer',
                  'aqueduct', 'conduit', 'wellspring', 'cistern', 'torrent',
                  'maelstrom', 'confluenc', 'rippl', 'reflect', 'mirror'],
        'weight': 3,
    },
    'invisible_forces': {
        'words': {
            'POLARITY', 'MAGNETIC', 'LODESTONE', 'MOMENTUM', 'INERTIA',
            'HARMONIC', 'RESONANCE', 'VORTEX', 'GRADIENT', 'ENTROPY',
            'CATALYSIS', 'CATALYST', 'DIFFUSION', 'OSCILLATE', 'PENDULUM',
            'GYROSCOPE', 'TELLURIC', 'GALVANIC', 'AEOLIAN', 'SEISMIC',
        },
        'roots': ['magnet', 'polar', 'lodeston', 'momentum', 'inertia',
                  'harmonic', 'resonanc', 'vortex', 'gradient', 'entropy',
                  'catalys', 'diffus', 'oscillat', 'pendulum', 'gyroscop',
                  'telluric', 'galvanic', 'aeolian', 'seismic', 'flux'],
        'weight': 4,
    },
    'archaeology_egypt': {
        'words': {
            'OBELISK', 'CARTOUCHE', 'SARCOPHAGUS', 'COLOPHON', 'CENOTAPH',
            'ARTIFACT', 'ANTIQUITY', 'NECROPOLIS', 'DOLMEN', 'MONOLITH',
            'ZIGGURAT', 'CITADEL', 'ACROPOLIS', 'SEPULCHER', 'TALISMAN',
            'AMULET', 'PEDESTAL', 'EPITAPH', 'MEGALITH', 'CEREMENT',
            'FERETRUM', 'CATACOMB', 'RELIQUARY',
        },
        'roots': ['obelisk', 'cartouche', 'sarcophag', 'colophon', 'cenotaph',
                  'artifact', 'antiquit', 'necropol', 'dolmen', 'monolith',
                  'ziggurat', 'citadel', 'acropol', 'sepulch', 'talisman',
                  'amulet', 'pedestal', 'epitaph', 'megalith', 'excavat',
                  'hieroglyph', 'papyrus', 'inscript', 'stele', 'relic'],
        'weight': 5,
    },
    'sculpture_materials': {
        'words': {
            'VERDIGRIS', 'PATINA', 'FILIGREE', 'ARMATURE', 'PEDESTAL',
            'COLOPHON', 'TRIPTYCH', 'ESCUTCHEON', 'REVETEMENT', 'OUBLIETTE',
            'FRIEZE', 'CORNICE', 'PILASTER', 'CARYATID', 'GARGOYLE',
            'BUTTRESS', 'PARAPET', 'PINNACLE', 'CUPOLA', 'ROTUNDA',
            'COLONNADE', 'PAVILION', 'PORTICO', 'ALCOVE', 'GROTTO',
            'CLOISTER', 'ATRIUM', 'BASILICA', 'MAUSOLEUM',
        },
        'roots': ['verdigris', 'patina', 'filigree', 'armatur', 'triptych',
                  'escutcheon', 'oubliet', 'frieze', 'cornice', 'pilaster',
                  'caryatid', 'gargoyl', 'buttress', 'parapet', 'pinnacl',
                  'cupola', 'rotunda', 'colonnad', 'pavilion', 'portico',
                  'alcove', 'grotto', 'cloister', 'atrium', 'basili',
                  'sculpt', 'engrav', 'carv', 'etch', 'inscrib', 'copper',
                  'bronze', 'marble', 'granite', 'obsidian', 'basalt'],
        'weight': 5,
    },
    'navigation_passage': {
        'words': {
            'COMPASS', 'AZIMUTH', 'TRAVERSE', 'LABYRINTH', 'THRESHOLD',
            'CROSSING', 'CORRIDOR', 'VESTIBULE', 'GATEWAY', 'SENTINEL',
            'WAYPOINT', 'LANDMARK', 'BEARING', 'HEADING', 'MERIDIAN',
            'SEXTANT', 'ASTROLABE', 'THEODOLITE', 'LODESTONE',
        },
        'roots': ['compass', 'azimuth', 'travers', 'labyrinth', 'threshold',
                  'crossing', 'corridor', 'vestibul', 'gateway', 'sentinel',
                  'waypoint', 'landmark', 'bearing', 'heading', 'meridian',
                  'sextant', 'astrolab', 'theodoli', 'lodeston', 'navigat',
                  'beacon', 'transit', 'passage', 'portal', 'conduit'],
        'weight': 4,
    },
}

# Known Sanborn keywords for calibration (what a 10/10 looks like)
SANBORN_KEYWORDS = {
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'VERDIGRIS', 'CENOTAPH',
    'FILIGREE', 'PARALLAX', 'GNOMON', 'ESCUTCHEON', 'TRIPTYCH',
    'COLOPHON', 'ARMATURE', 'OCULUS', 'DOLMEN', 'OUBLIETTE', 'REVETEMENT',
}


def score_plausibility(word: str, pos: str, gloss: str) -> tuple[float, list[str], str]:
    """
    Score a word for constructor plausibility.
    Returns (score, domain_hits, rarity_class).
    """
    w = word.upper()
    wl = word.lower()
    L = len(w)
    score = 0.0
    domains_hit = []

    # ── Domain matching ──────────────────────────────────────────────────
    for domain_name, domain in DOMAIN_SCORES.items():
        hit = False
        # Exact word match
        if w in domain['words']:
            score += domain['weight']
            hit = True
        # Root/substring match
        for root in domain['roots']:
            if root in wl:
                score += domain['weight'] * 0.6
                hit = True
                break
        if hit:
            domains_hit.append(domain_name)

    # ── Known Sanborn keyword bonus ──────────────────────────────────────
    if w in SANBORN_KEYWORDS:
        score += 10  # calibration anchor

    # ── Lexical compactness bonus ────────────────────────────────────────
    # Sanborn prefers compact, precise words
    if 7 <= L <= 9:
        score += 2.0
    elif 5 <= L <= 11:
        score += 1.0
    elif L >= 14:
        score -= 1.0

    # ── POS bonus ────────────────────────────────────────────────────────
    if pos == 'noun':
        score += 2.0
    elif pos == 'adj':
        score += 0.5

    # ── Gloss-based domain matching ──────────────────────────────────────
    # Architecture / sculpture / archaeology in gloss
    if re.search(r'(?i)\b(architect|column|pillar|monument|sculpture|'
                 r'fortif|castle|tower|arch\b|vault|dome|temple|shrine|'
                 r'tomb|burial|funerar|ancient|greek|roman\b|latin|'
                 r'egypt|pharaoh|pyramid|hieroglyph|inscript|engrav|carv|'
                 r'cipher|code\b|secret|conceal|hidden|cryptograph|'
                 r'compass|navigat|astro|optic|sundial|'
                 r'mineral|crystal|stone|marble|bronze|copper|'
                 r'masonry|heraldry|emblem|insignia|'
                 r'museum|gallery|artifact|relic|antiq|'
                 r'ornament|decorat|motif|relief)\b', gloss):
        score += 2.0

    # Science / physics / geometry in gloss
    if re.search(r'(?i)\b(geometry|mathematic|algebra|trigonometr|'
                 r'physic|optic|magnetic|electric|wave|field|'
                 r'coordinate|projection|transformation|symmetr|'
                 r'astronomy|celestial|planetary|orbit|'
                 r'cartograph|survey|geodesy|triangulat)\b', gloss):
        score += 1.5

    # Renaissance / medieval / classical in gloss
    if re.search(r'(?i)\b(classical|medieval|renaissance|baroque|gothic|'
                 r'antiquarian|neoclassic|palladian)\b', gloss):
        score += 1.0

    # Negative gloss domains (not hard reject, but penalize)
    if re.search(r'(?i)\b(slang|informal|colloquial|vulgar|offensive|'
                 r'brand|trademark|computing|programming)\b', gloss):
        score -= 2.0

    # ── Conceptual precision bonus ───────────────────────────────────────
    # Words that name a specific object or concept (vs abstract generics)
    if re.search(r'(?i)\b(device|instrument|tool|apparatus|mechanism)\b', gloss):
        score += 1.0
    # Words that name a type of structure
    if re.search(r'(?i)\b(type of|form of|kind of|style of)\b.*\b(building|structure|column|arch|'
                 r'stone|monument|ornament|cipher|code)\b', gloss):
        score += 1.5

    # ── Rarity classification ────────────────────────────────────────────
    rarity = 'common'
    if score >= 3 and L <= 12 and domains_hit:
        rarity = 'thematic'
    elif score >= 1.5 and domains_hit:
        rarity = 'rare-but-plausible'
    elif score < 0:
        rarity = 'implausible'
    elif score == 0 and not domains_hit:
        rarity = 'unthematic'

    return round(score, 1), domains_hit, rarity


# ═══════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def main():
    base_dir = os.path.join(os.path.dirname(__file__), '..', '..')
    tsv_path = os.path.join(base_dir, 'results', 'bean_keywords', 'bean_keywords_ranked.tsv')
    tsv_path = os.path.abspath(tsv_path)

    if not os.path.exists(tsv_path):
        print(f"ERROR: Run e_bean_keyword_filter.py first to generate {tsv_path}")
        sys.exit(1)

    print("Loading Bean-passing words...")
    raw_words = load_bean_words(tsv_path)
    print(f"  Loaded {len(raw_words)} Bean-passing words")

    # ── Phase 1: Hard rejection ──────────────────────────────────────────
    print("\n=== Phase 1: Hard Rejection ===")
    passed = []
    rejected = []
    reject_counts = defaultdict(int)

    for entry in raw_words:
        reason = hard_reject(entry['word'], entry['pos'], entry['gloss'])
        if reason:
            rejected.append({**entry, 'reject_reason': reason})
            reject_counts[reason.split('(')[0].strip()] += 1
        else:
            passed.append(entry)

    print(f"  Passed: {len(passed)}")
    print(f"  Rejected: {len(rejected)}")
    print(f"  Rejection breakdown:")
    for reason, count in sorted(reject_counts.items(), key=lambda x: -x[1]):
        print(f"    {reason:45s} {count:5d}")

    # ── Phase 2: Plausibility scoring ────────────────────────────────────
    print("\n=== Phase 2: Plausibility Scoring ===")
    candidates = []

    for entry in passed:
        # Score plausibility
        plaus_score, domains, rarity = score_plausibility(
            entry['word'], entry['pos'], entry['gloss']
        )

        # Apply soft penalties
        penalties = soft_penalties(entry['word'], entry['pos'], entry['gloss'])
        penalty_total = sum(p for _, p in penalties)
        penalty_reasons = [r for r, _ in penalties]

        final_score = plaus_score + penalty_total

        candidates.append({
            'word': entry['word'],
            'length': entry['length'],
            'pos': entry['pos'],
            'plausibility': round(final_score, 1),
            'raw_plausibility': plaus_score,
            'domains': domains,
            'rarity': rarity,
            'penalties': penalty_reasons,
            'gloss': entry['gloss'],
            'eq_pos': entry['eq_pos'],
        })

    # Sort by plausibility descending
    candidates.sort(key=lambda x: (-x['plausibility'], x['word']))

    # ── Stats ────────────────────────────────────────────────────────────
    print(f"\n  Total scored: {len(candidates)}")
    len_dist = defaultdict(int)
    for c in candidates:
        len_dist[c['length']] += 1
    print(f"  Length distribution:")
    for l in sorted(len_dist):
        print(f"    Length {l:2d}: {len_dist[l]:5d}")

    rarity_dist = defaultdict(int)
    for c in candidates:
        rarity_dist[c['rarity']] += 1
    print(f"  Rarity distribution:")
    for r, count in sorted(rarity_dist.items(), key=lambda x: -x[1]):
        print(f"    {r:25s} {count:5d}")

    # ═══════════════════════════════════════════════════════════════════════
    # DELIVERABLES
    # ═══════════════════════════════════════════════════════════════════════

    def fmt(c, idx):
        """Format a candidate for display."""
        domains = ','.join(c['domains'][:3]) if c['domains'] else '-'
        pen = f"  [{'; '.join(c['penalties'])}]" if c['penalties'] else ''
        return (f"{idx:3d}. {c['word']:22s}  len={c['length']:2d}  "
                f"score={c['plausibility']:5.1f}  "
                f"pos={c['pos']:5s}  "
                f"domains={domains:40s}  "
                f"rarity={c['rarity']:20s}"
                f"{pen}")

    def fmt_detail(c, idx):
        """Format with gloss."""
        domains = ','.join(c['domains'][:3]) if c['domains'] else '-'
        gloss = c['gloss'][:80] if c['gloss'] else '-'
        pen = f"\n       Penalties: {'; '.join(c['penalties'])}" if c['penalties'] else ''
        return (f"{idx:3d}. {c['word']:22s}  len={c['length']:2d}  "
                f"score={c['plausibility']:5.1f}  pos={c['pos']:5s}\n"
                f"       Domains: {domains}\n"
                f"       Gloss: {gloss}"
                f"{pen}")

    # ── TOP 100 ──────────────────────────────────────────────────────────
    print("\n" + "=" * 100)
    print("TOP 100 SERIOUS CANDIDATES")
    print("=" * 100)
    top100 = candidates[:100]
    for i, c in enumerate(top100, 1):
        print(fmt(c, i))

    # ── TOP 25 STRONGEST ─────────────────────────────────────────────────
    print("\n" + "=" * 100)
    print("TOP 25 STRONGEST CANDIDATES (detailed)")
    print("=" * 100)
    top25 = candidates[:25]
    for i, c in enumerate(top25, 1):
        print(fmt_detail(c, i))
        print()

    # ── TOP 25 RARE-BUT-PLAUSIBLE ────────────────────────────────────────
    print("\n" + "=" * 100)
    print("TOP 25 RARE-BUT-PLAUSIBLE CANDIDATES")
    print("=" * 100)
    top25_words = {c['word'] for c in top25}
    rare = [c for c in candidates
            if c['rarity'] in ('rare-but-plausible', 'thematic')
            and c['word'] not in top25_words
            and c['plausibility'] >= 1.0][:25]
    for i, c in enumerate(rare, 1):
        print(fmt_detail(c, i))
        print()

    # ── 25 BORDERLINE ────────────────────────────────────────────────────
    print("\n" + "=" * 100)
    print("25 BORDERLINE CANDIDATES")
    print("=" * 100)
    used = top25_words | {c['word'] for c in rare}
    borderline = [c for c in candidates
                  if 0 < c['plausibility'] < 3
                  and c['word'] not in used
                  and not c['penalties']][:25]
    for i, c in enumerate(borderline, 1):
        print(fmt(c, i))

    # ── 20 REJECTED EXAMPLES ─────────────────────────────────────────────
    print("\n" + "=" * 100)
    print("20 REJECTED EXAMPLES (with explanations)")
    print("=" * 100)
    # Pick interesting/diverse rejections
    seen_reasons = set()
    rej_examples = []
    for r in rejected:
        reason_key = r['reject_reason'].split('(')[0].strip()
        if reason_key not in seen_reasons or len(rej_examples) < 20:
            rej_examples.append(r)
            seen_reasons.add(reason_key)
        if len(rej_examples) >= 20:
            break
    for i, r in enumerate(rej_examples, 1):
        gloss_short = r['gloss'][:60] if r['gloss'] else '-'
        print(f"{i:3d}. {r['word']:25s}  len={r['length']:2d}  pos={r['pos']:5s}  "
              f"REJECTED: {r['reject_reason']}")
        print(f"       Gloss: {gloss_short}")

    # ── Write results ────────────────────────────────────────────────────
    out_dir = os.path.join(base_dir, 'results', 'bean_keywords')
    os.makedirs(out_dir, exist_ok=True)

    # JSON with all deliverables
    out_path = os.path.join(out_dir, 'plausibility_results.json')
    output = {
        'summary': {
            'total_bean_passing': len(raw_words),
            'passed_hard_filter': len(passed),
            'hard_rejected': len(rejected),
            'rejection_breakdown': dict(reject_counts),
            'rarity_distribution': dict(rarity_dist),
            'length_distribution': {str(k): v for k, v in sorted(len_dist.items())},
            'bean_compatible_lengths': sorted(len_dist.keys()),
        },
        'top_100': [{k: v for k, v in c.items()} for c in top100],
        'top_25_strongest': [{k: v for k, v in c.items()} for c in top25],
        'top_25_rare_but_plausible': [{k: v for k, v in c.items()} for c in rare],
        'borderline_25': [{k: v for k, v in c.items()} for c in borderline],
        'rejected_examples': [{k: v for k, v in r.items()} for r in rej_examples],
    }
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {out_path}")

    # Priority wordlist (top candidates only, for campaign use)
    priority_path = os.path.join(out_dir, 'plausibility_priority_words.txt')
    with open(priority_path, 'w') as f:
        for c in candidates:
            if c['plausibility'] >= 2.0:
                f.write(c['word'] + '\n')
    priority_count = sum(1 for c in candidates if c['plausibility'] >= 2.0)
    print(f"Priority wordlist ({priority_count} words): {priority_path}")

    # ── Final evaluation ─────────────────────────────────────────────────
    print("\n" + "=" * 100)
    print("FINAL EVALUATION")
    print("=" * 100)
    print("\nWould a rational human constructor plausibly choose this word for Kryptos?")
    print("\nTop 10 most plausible keywords:")
    for i, c in enumerate(candidates[:10], 1):
        domains = ', '.join(c['domains'][:3]) if c['domains'] else 'none'
        print(f"  {i:2d}. {c['word']:20s}  ({domains})")
        print(f"      {c['gloss'][:100]}")
    print()

    # Cross-check: which known Sanborn keywords would pass our filter?
    print("Known Sanborn keyword cross-check (if they were Bean-compatible):")
    for kw in sorted(SANBORN_KEYWORDS):
        pscore, domains, rarity = score_plausibility(kw, 'noun', '')
        print(f"  {kw:15s}  plausibility={pscore:5.1f}  domains={','.join(domains[:3]) if domains else '-'}")


if __name__ == '__main__':
    main()
