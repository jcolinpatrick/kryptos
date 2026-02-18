"""
K4 Word-constrained plaintext search.

Instead of quadgram SA (which converges to gibberish), search for plaintexts
composed of actual English words that fit the thematic constraints:
- 1986 Egypt trip
- 1989 Berlin Wall fall
- "Delivering a message"
- "What's the point?"
- CIA / intelligence themes

Strategy: build candidate plaintexts from word fragments that could appear
in the three free zones (pre-ENE, mid, post-BC), and check if the resulting
keystream shows structure (periodicity, English text, or known patterns).
"""
import sys, json, time
from collections import Counter
sys.path.insert(0, '/home/cpatrick/kryptos/src')

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

ENE_POS, ENE_PT = 21, 'EASTNORTHEAST'
BC_POS, BC_PT = 63, 'BERLINCLOCK'

def c2n(c): return ord(c) - ord('A')
def n2c(n): return chr(n % 26 + ord('A'))

# Known key values (Vig)
known_vig = {}
for start, pt in [(ENE_POS, ENE_PT), (BC_POS, BC_PT)]:
    for i, ch in enumerate(pt):
        pos = start + i
        known_vig[pos] = (CT_NUM[pos] - c2n(ch)) % 26

# Load quadgrams
QG_PATH = '/home/cpatrick/kryptos/data/english_quadgrams.json'
with open(QG_PATH) as f:
    quadgrams = json.load(f)

FLOOR = -10.0

def qg_score(text):
    score = 0.0
    for i in range(len(text) - 3):
        score += quadgrams.get(text[i:i+4], FLOOR)
    return score

def vig_key(pt_text):
    return [(CT_NUM[i] - c2n(pt_text[i])) % 26 for i in range(len(pt_text))]

def key_text(key_nums):
    return ''.join(n2c(k) for k in key_nums)

# Bean constraint: k[27] = k[65]
# PT[27] from ENE crib = 'R' → k[27] = (CT[27] - c2n('R')) % 26 = (15 - 17) % 26 = 24
# So k[65] must = 24 → PT[65] = (CT[65] - 24) % 26 = (15 - 24) % 26 = 17 = 'R'
# PT[65] is the 3rd char of BERLINCLOCK = 'R'. Already satisfied by crib. ✓

# ============================================================
# THEMATIC WORD BANKS
# ============================================================
# Zone 1: positions 0-20 (21 chars)
# Zone 2: positions 34-62 (29 chars)
# Zone 3: positions 74-96 (23 chars)

# Thematic words/phrases that might appear
thematic_words = [
    # Delivery / message theme
    'THE', 'MESSAGE', 'WAS', 'DELIVERED', 'TO', 'FROM',
    'SENT', 'TRANSMITTED', 'RECEIVED', 'CODED', 'SECRET',
    'HIDDEN', 'BURIED', 'FOUND', 'DISCOVERED', 'REVEALED',
    'DECODED', 'ENCRYPTED', 'CLASSIFIED', 'INTELLIGENCE',
    # Egypt 1986
    'EGYPT', 'CAIRO', 'NILE', 'PYRAMID', 'PHARAOH', 'TOMB',
    'TUTANKHAMEN', 'CARTER', 'DESERT', 'SAND', 'ANCIENT',
    'EXCAVATION', 'DISCOVERY', 'ARTIFACT', 'HIEROGLYPHIC',
    'SLOWLY', 'DESPERATELY',
    # Berlin 1989
    'BERLIN', 'WALL', 'FELL', 'NOVEMBER', 'NINETEEN',
    'EIGHTY', 'NINE', 'GERMANY', 'EAST', 'WEST',
    'FREEDOM', 'GATE', 'CHECKPOINT', 'CHARLIE',
    # CIA / intelligence
    'CIA', 'LANGLEY', 'AGENCY', 'DIRECTOR', 'OPERATION',
    'COVERT', 'MISSION', 'FIELD', 'AGENT', 'STATION',
    'HEADQUARTERS', 'VIRGINIA', 'WASHINGTON',
    # Kryptos-specific
    'SHADOW', 'LIGHT', 'POINT', 'MAGNETIC', 'COMPASS',
    'COORDINATES', 'LOCATION', 'DIRECTION',
    'IQLUSION', 'PALIMPSEST', 'ABSCISSA', 'KRYPTOS',
    'INVISIBLE', 'UNDERGROUND', 'UNKNOWN',
    # "What's the point?"
    'WHATS', 'THE', 'POINT', 'QUESTION',
    # Connectors
    'IN', 'OF', 'AND', 'AT', 'BY', 'FOR', 'WITH', 'ON',
    'THAT', 'THIS', 'THEIR', 'THEY', 'WERE', 'HAD',
    'IT', 'IS', 'NOT', 'BUT', 'WHICH', 'WHEN', 'WHERE',
    'AFTER', 'BEFORE', 'DURING', 'BETWEEN',
    'X',  # K2-style separator
]

# Deduplicate
thematic_words = list(set(thematic_words))

print("=" * 70)
print("K4 WORD-CONSTRAINED PLAINTEXT SEARCH")
print("=" * 70)
print(f"Word bank: {len(thematic_words)} words")

# ============================================================
# APPROACH 1: Exhaustive word combinations for each zone
# ============================================================

def fill_zone(target_len, words, max_combos=50000):
    """Generate all possible word combinations that fill exactly target_len characters."""
    results = []

    def backtrack(current, remaining):
        if remaining == 0:
            results.append(current)
            if len(results) >= max_combos:
                return
            return
        if remaining < 0:
            return
        for word in words:
            if len(word) <= remaining:
                backtrack(current + word, remaining - len(word))
                if len(results) >= max_combos:
                    return

    backtrack('', target_len)
    return results

# Zone sizes
ZONE1_LEN = 21  # pos 0-20
ZONE2_LEN = 29  # pos 34-62
ZONE3_LEN = 23  # pos 74-96

# Filter words by relevance and length
short_words = [w for w in thematic_words if len(w) <= 12]

print(f"\nGenerating zone fills (may take a while)...")
t0 = time.time()

# For efficiency, use a smaller word set for combination search
# and score resulting keys
core_words = [
    # Short connectors
    'THE', 'IN', 'OF', 'AND', 'AT', 'BY', 'TO', 'FOR', 'ON', 'IT', 'IS', 'WAS',
    'NOT', 'BUT', 'X',
    # Thematic 3-5 letter
    'SENT', 'FROM', 'EAST', 'WEST', 'WALL', 'FELL', 'NINE', 'SAND',
    'TOMB', 'NILE', 'GATE', 'CIA', 'FIELD', 'AGENT', 'CODED', 'FOUND',
    'POINT', 'LIGHT', 'SHADOW', 'HIDDEN',
    # Thematic 6-8 letter
    'SECRET', 'BERLIN', 'DESERT', 'BURIED', 'SLOWLY', 'EGYPT',
    'DECODED', 'MESSAGE', 'MISSION', 'COVERT', 'SHADOW',
    'WHATS',
]
core_words = list(set(core_words))

# More targeted: specific phrases that might start zones
zone1_starters = [
    'ITWASBURIEDINTHE',  # 16 + 5 more
    'THEMESSAGEWASFROM',  # 17 + 4
    'SLOWLYDESPERATELY',  # 18 + 3
    'THESECRETMESSAGEW',  # 17 + 4
    'DELIVERINGAMESSAG',  # 17 + 4
    'THEMESSAGEWASSENT',  # 17 + 4
    'INTHEDIRECTIONOFX',  # 18 + 3
    'FROMTHEDESERTINEG',  # 17 + 4
    'POINTEDINTHEDIREC',  # 17 + 4
    'ITSHOULDBEBURIEDX',  # 17 + 4
    'ITWASTRANSMITTEDT',  # 17 + 4
    'ITSTARTEDWITHAXME',  # 17 + 4
    'ATHENSSAIDLANGLEY',  # 17 + 4
    'INTHENORTHEASTDIR',  # 17 + 4
    'THECOORDINATESWER',  # 17 + 4
    'WHATISTHEPOINTWHY',  # 17 + 4
    'DIGSLOWLYDESPERT',   # 17 + 4
    'WHATSTHEPOINTOFIT',  # 17 + 4
    'WITHOUTANYPOINTTO',  # 17 + 4
]

zone2_starters = [
    'THEREWASNOESCAPEFROMBERLIN',     # 26 + 3
    'WHENTHEWALLFELLINNOVEMBER',       # 26 + 3
    'TOTHEBERLINWALLBEFOREITFELL',     # 29 exact
    'ANDTHEMESSAGEWASTRANSMITTED',     # 29
    'BEFORETHEFALLOFTHEBERLINWA',       # 28 + 1
    'FROMTHEDESERTANDTHENACROSS',       # 28 + 1
    'NOTONLYINEGYPTBUTALSOINGERM',     # 30 too long
    'THEWALLFALLANDTHEMESSAGEWA',       # 28 + 1
    'SENTFROMCAIROTOBERLINBEFORE',      # 29
    'INTHEFALLOFNINETEENEIGHTYN',       # 28 + 1
    'AFTERNINETEENEIGHTYSIXTHEY',       # 27 + 2
    'TODELIVERTHEMESSAGETOTHEXI',       # 28 + 1
    'WASDELIVEREDVIATHEXUNDERXGR',     # 29
    'INTHEYEARNINETEENEIGHTYNIN',       # 28 + 1
    'INNINETEEN EIGHTYNINETHEWAL',     # spaces
    'THEREWASASECRETMESSAGEFROM',       # 28 + 1
    'ITALLSTARTEDWITHAXMESSAGEF',       # 28 + 1
]

zone3_starters = [
    'ASKEDWHATSTHEPOINTXXX',  # 21 + 2
    'ANDWHATSTHEPOINTOFTH', # 20 + 3
    'WHATSTHEPOINTOFITALL', # 21 + 2
    'INTHEENDWHATSTHEPOINT', # 22 + 1
    'ITSBURIEDOUTTHERESOME', # 21 + 2
    'THEYWONDEREDWHYXXXXX',  # 20 + 3
    'BUTWHATSTHEPOINTOFXX',  # 20 + 3
    'SHADOWANDLIGHTXXXXXX',  # 20 + 3
    'WHATSTHEPOINTANYWAYX',  # 20 + 3
    'ONLYWWKNOWSABOUTTHIS', # 21 + 2
    'THEANSWERWASBURIEDXX',  # 20 + 3
    'THATISTHEWHOLEPOINTO', # 21 + 2
    'ISTHEREAPOINTTOITALL', # 21 + 2
]

def pad(s, target):
    s = s.replace(' ', '').upper()
    s = ''.join(c for c in s if c.isalpha())
    if len(s) > target:
        s = s[:target]
    while len(s) < target:
        s += 'X'
    return s

print(f"\nTesting {len(zone1_starters)} × {len(zone2_starters)} × {len(zone3_starters)} = "
      f"{len(zone1_starters) * len(zone2_starters) * len(zone3_starters)} combinations")

best_results = []

for z1 in zone1_starters:
    z1 = pad(z1, ZONE1_LEN)
    for z2 in zone2_starters:
        z2 = pad(z2, ZONE2_LEN)
        for z3 in zone3_starters:
            z3 = pad(z3, ZONE3_LEN)
            pt = z1 + ENE_PT + z2 + BC_PT + z3
            assert len(pt) == N, f"len={len(pt)}"

            # Quick check: Bean constraint
            k27 = (CT_NUM[27] - c2n(pt[27])) % 26
            k65 = (CT_NUM[65] - c2n(pt[65])) % 26
            if k27 != k65:
                continue

            # Compute key and score
            key = vig_key(pt)
            kt = key_text(key)

            # Score both PT and key
            pt_score = qg_score(pt)
            key_score = qg_score(kt)
            combined = pt_score + key_score

            best_results.append((combined, pt_score, key_score, pt, kt))

# Sort by combined score
best_results.sort(reverse=True)

print(f"\nBean-passing candidates: {len(best_results)}")
print(f"\nTOP 20 BY COMBINED PT+KEY QUADGRAM SCORE:")
print("-" * 70)
for i, (combined, pt_s, key_s, pt, kt) in enumerate(best_results[:20]):
    print(f"\n#{i+1} combined={combined:.0f} (pt={pt_s:.0f}, key={key_s:.0f})")
    print(f"  PT:  {pt[:21]}|{ENE_PT}|{pt[34:63]}|{BC_PT}|{pt[74:]}")
    print(f"  Key: {kt}")

# ============================================================
# APPROACH 2: Check if ANY known text at specific key position
# produces readable key
# ============================================================
print("\n" + "=" * 70)
print("APPROACH 2: KEY READABILITY SEARCH")
print("=" * 70)

# The known key at cribs is: BLZCDCYYGCKAZ...MUYKLGKORNA
# If the key is English text, what words could contain BLZCDCYYGCKAZ?
# This is clearly NOT English (BLZ, CDY, YGC are not English bigrams)
# But what if we're wrong about the cipher variant?
# Under Beaufort: key = CT + PT mod 26
# Beaufort key at ENE: positions 21-33
beau_key_ene = [(CT_NUM[i] + c2n(ENE_PT[i-21])) % 26 for i in range(21, 34)]
beau_key_bc = [(CT_NUM[i] + c2n(BC_PT[i-63])) % 26 for i in range(63, 74)]
print(f"\nBeaufort key at ENE (21-33): {''.join(n2c(k) for k in beau_key_ene)}")
print(f"Beaufort key at BC  (63-73): {''.join(n2c(k) for k in beau_key_bc)}")

# Under KA-Vigenère
KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_MAP = {c: i for i, c in enumerate(KA)}
ka_key_ene = [(KA_MAP[CT[i]] - KA_MAP[ENE_PT[i-21]]) % 26 for i in range(21, 34)]
ka_key_bc = [(KA_MAP[CT[i]] - KA_MAP[BC_PT[i-63]]) % 26 for i in range(63, 74)]
print(f"\nKA-Vig key at ENE (21-33): {''.join(KA[k] for k in ka_key_ene)}")
print(f"KA-Vig key at BC  (63-73): {''.join(KA[k] for k in ka_key_bc)}")

# Under KA-Beaufort
ka_beau_ene = [(KA_MAP[CT[i]] + KA_MAP[ENE_PT[i-21]]) % 26 for i in range(21, 34)]
ka_beau_bc = [(KA_MAP[CT[i]] + KA_MAP[BC_PT[i-63]]) % 26 for i in range(63, 74)]
print(f"\nKA-Beau key at ENE (21-33): {''.join(KA[k] for k in ka_beau_ene)}")
print(f"KA-Beau key at BC  (63-73): {''.join(KA[k] for k in ka_beau_bc)}")

# ============================================================
# APPROACH 3: DICTIONARY WORDS IN KEY
# ============================================================
print("\n" + "=" * 70)
print("APPROACH 3: SEARCH FOR ENGLISH WORDS IN KEY FRAGMENTS")
print("=" * 70)

# Load dictionary
dict_path = '/home/cpatrick/kryptos/wordlists/english.txt'
with open(dict_path) as f:
    dictionary = set(w.strip().upper() for w in f if len(w.strip()) >= 4)

print(f"Dictionary size: {len(dictionary)} words (len ≥ 4)")

# For each variant, check if key fragments at crib positions contain dictionary words
for variant_name, key_ene, key_bc in [
    ("AZ-Vig", [known_vig[i] for i in range(21,34)], [known_vig[i] for i in range(63,74)]),
    ("Beaufort", beau_key_ene, beau_key_bc),
    ("KA-Vig", ka_key_ene, ka_key_bc),
    ("KA-Beau", ka_beau_ene, ka_beau_bc),
]:
    if variant_name.startswith("KA"):
        ene_str = ''.join(KA[k] for k in key_ene)
        bc_str = ''.join(KA[k] for k in key_bc)
    else:
        ene_str = ''.join(n2c(k) for k in key_ene)
        bc_str = ''.join(n2c(k) for k in key_bc)

    # Find words in ENE key fragment
    words_ene = []
    for start in range(len(ene_str)):
        for end in range(start + 4, len(ene_str) + 1):
            substr = ene_str[start:end]
            if substr in dictionary:
                words_ene.append((start, substr))

    # Find words in BC key fragment
    words_bc = []
    for start in range(len(bc_str)):
        for end in range(start + 4, len(bc_str) + 1):
            substr = bc_str[start:end]
            if substr in dictionary:
                words_bc.append((start, substr))

    if words_ene or words_bc:
        print(f"\n  {variant_name}:")
        print(f"    ENE key: {ene_str}")
        print(f"    BC  key: {bc_str}")
        for pos, word in words_ene:
            print(f"    ENE: '{word}' at offset {pos}")
        for pos, word in words_bc:
            print(f"    BC:  '{word}' at offset {pos}")

print("\n" + "=" * 70)
print("WORD-CONSTRAINED SEARCH COMPLETE")
print("=" * 70)
