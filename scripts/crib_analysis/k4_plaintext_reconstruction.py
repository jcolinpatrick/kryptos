"""
Cipher: crib-based constraint
Family: crib_analysis
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Plaintext reconstruction attack on K4.
Given the cribs and thematic clues, construct candidate plaintexts and
score the resulting keystream for structure (English, patterns, math).
"""
import sys, json, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_DIR = Path(os.getenv("K4_BASE_DIR", str(REPO_ROOT)))

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

def c2n(c): return ord(c) - ord('A')
def n2c(n): return chr(n % 26 + ord('A'))

# Load quadgram scorer
QUADGRAM_PATH = str(BASE_DIR / "data" / "english_quadgrams.json")
quadgrams = {}
if os.path.exists(QUADGRAM_PATH):
    with open(QUADGRAM_PATH) as f:
        data = json.load(f)
    if 'logp' in data:
        quadgrams = data['logp']
    else:
        quadgrams = data

def quadgram_score(text):
    """Score text by sum of log10 quadgram frequencies."""
    if not quadgrams:
        return 0.0
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        if qg in quadgrams:
            score += quadgrams[qg]
        else:
            score += -10.0  # penalty for unseen quadgram
    return score

def compute_key(pt_text):
    """Given a 97-char plaintext, compute the Vigenère keystream."""
    assert len(pt_text) == N
    return [(CT_NUM[i] - c2n(pt_text[i])) % 26 for i in range(N)]

def key_to_text(key_nums):
    return ''.join(n2c(k) for k in key_nums)

def score_key_structure(key_nums):
    """Score how 'structured' a keystream is. Higher = more structured."""
    key_text = key_to_text(key_nums)
    scores = {}

    # 1. Quadgram score of key-as-text
    scores['key_quadgram'] = quadgram_score(key_text)

    # 2. Check for periodicity
    best_period_score = 0
    for p in range(1, 49):
        matches = sum(1 for i in range(p, N) if key_nums[i] == key_nums[i - p])
        expected = (N - p) / 26
        score = (matches - expected) / max(1, expected**0.5)
        if score > best_period_score:
            best_period_score = score
    scores['best_periodicity_z'] = best_period_score

    # 3. Count distinct values
    scores['distinct_values'] = len(set(key_nums))

    # 4. Check for arithmetic progressions
    diffs = [(key_nums[i+1] - key_nums[i]) % 26 for i in range(N-1)]
    most_common_diff = max(set(diffs), key=diffs.count)
    scores['most_common_diff_count'] = diffs.count(most_common_diff)

    # 5. Count zeros (self-encrypting)
    scores['zero_count'] = key_nums.count(0)

    # 6. IC of key
    from collections import Counter
    freq = Counter(key_nums)
    ic = sum(f * (f-1) for f in freq.values()) / (N * (N-1)) if N > 1 else 0
    scores['key_ic'] = ic

    return scores

def format_scores(scores):
    parts = []
    parts.append(f"qg={scores['key_quadgram']:.0f}")
    parts.append(f"per_z={scores['best_periodicity_z']:.1f}")
    parts.append(f"dist={scores['distinct_values']}")
    parts.append(f"zeros={scores['zero_count']}")
    parts.append(f"ic={scores['key_ic']:.4f}")
    return " ".join(parts)

print("=" * 70)
print("K4 PLAINTEXT RECONSTRUCTION ATTACK")
print("=" * 70)

# ============================================================
# CANDIDATE PLAINTEXT GENERATION
# ============================================================
# Constraints:
# pos 0-20: 21 chars
# pos 21-33: EASTNORTHEAST (fixed)
# pos 34-62: 29 chars
# pos 63-73: BERLINCLOCK (fixed)
# pos 74-96: 23 chars

ENE = 'EASTNORTHEAST'
BC = 'BERLINCLOCK'

# Thematic phrases to try at various positions
phrases = {
    # Pre-ENE (pos 0-20, 21 chars)
    'pre_ene': [
        'SLOWLYDESPARATLYSLOWL',  # K3 reference
        'BETWEENSUBLIMINALSIGN',
        'THEMESSAGEWASDIRECTED',
        'THEMESSAGEWASDELIVERD',
        'HEADINTHEDIRECTIONOFX',
        'ITWASSENTINTHEDIRECTI',
        'THELOCATIONWASXXXXXEN',
        'FROMEGYPTIANSANDSXXXX',
        'FROMCAIROINNINETEENEI',
        'DELIVERTHEMESSAGEXXXX',
        'THECOORDINATESWEREXXE',
        'WHICHPOINTEDTOWARDXXX',
        'HEHADTRAVELEDTOWARDSX',
        'SHADOWSINTHEDESERTXXX',
        'ITSHOULDHAVEBEENXXXXX',
        'FOLLOWTHEDIRECTIONSXX',
    ],
    # Mid section (pos 34-62, 29 chars)
    'mid': [
        'TOTHEBERLINWALLINNOVEMBERX',  # 25 - too short
        'XTHEWALLFELLONNOVEMBERNINTH',  # 27 - too short
        'XTODAYTHEMESSAGEREACHEDTHEX',  # 27
        'XTHEBERLINWALLFELLINXEIGHTY',  # 27
        'XTODAYWERECEIVEDNEWSFROMTHE',  # 27
        'XANDSOWEDECIDEDTODELIVERITX',
        'XWHENTHEWALLFELLINNOVEMBERX',
        'XTHEMESSAGEWASTRANSMITTEDTO',
        'ITHAPPENEDINNINETEEN EIGHTY',
        'XDIGITALLYSLOWLYTHEANSWERSX',
    ],
    # Post-BC (pos 74-96, 23 chars)
    'post_bc': [
        'SHOWEDITMATCHEDWHATSTH',  # 22 - one short
        'XWHATSTHEPOINTXSHADOWX',
        'XWHATSTHEPOINTXLIGHTXX',
        'XWHATSTHEPOINTXDELIVEX',
        'SHOWEDSIXTHIRTYTWOXXX',
        'XTHEYWONDEREDWHATSTHEP',
        'XANDSOWHATSTHEPOINTXX',
        'XBUTWHATSTHEPOINTOFIT',
        'XANDITWONDEREDWHATWAS',
        'XTHEREISNOPOINTTOITXX',
        'XWHATSTHEPOINTXASKEDS',
        'ITSALLABOUTTHEMESSAGE',
        'ITSALLABOUTDELIVERING',
        'SAIDWHATSTHEPOINTOFTH',
    ],
}

# Fix lengths
def pad_or_trim(s, target_len):
    s = s.replace(' ', '')
    if len(s) < target_len:
        s = s + 'X' * (target_len - len(s))
    return s[:target_len]

# Generate all candidates
candidates = []
for pre in phrases['pre_ene']:
    pre = pad_or_trim(pre, 21)
    for mid in phrases['mid']:
        mid = pad_or_trim(mid, 29)
        for post in phrases['post_bc']:
            post = pad_or_trim(post, 23)
            pt = pre + ENE + mid + BC + post
            assert len(pt) == 97, f"len={len(pt)}"
            candidates.append(pt)

print(f"Generated {len(candidates)} candidate plaintexts")
print()

# Score all candidates
results = []
for pt in candidates:
    key = compute_key(pt)
    scores = score_key_structure(key)
    key_text = key_to_text(key)
    results.append((pt, key, key_text, scores))

# Sort by quadgram score (higher is better = more English-like key)
results.sort(key=lambda x: x[3]['key_quadgram'], reverse=True)

print("TOP 20 BY KEY QUADGRAM SCORE (higher = more English-like key):")
print("-" * 70)
for i, (pt, key, key_text, scores) in enumerate(results[:20]):
    print(f"\n#{i+1} {format_scores(scores)}")
    print(f"  PT: {pt[:21]}|{pt[21:34]}|{pt[34:63]}|{pt[63:74]}|{pt[74:]}")
    print(f"  Key: {key_text}")

# Sort by periodicity z-score
results.sort(key=lambda x: x[3]['best_periodicity_z'], reverse=True)
print("\n\nTOP 10 BY KEY PERIODICITY Z-SCORE:")
print("-" * 70)
for i, (pt, key, key_text, scores) in enumerate(results[:10]):
    print(f"\n#{i+1} {format_scores(scores)}")
    print(f"  PT: {pt[:21]}|{pt[21:34]}|{pt[34:63]}|{pt[63:74]}|{pt[74:]}")
    print(f"  Key: {key_text}")

# ============================================================
# TARGETED: WHATSTHEPOINT EMBEDDING
# ============================================================
print("\n" + "=" * 70)
print("WHATSTHEPOINT EMBEDDING ANALYSIS")
print("=" * 70)

wtp = 'WHATSTHEPOINT'
wtp_num = [c2n(c) for c in wtp]

print(f"Testing '{wtp}' (len={len(wtp)}) at all valid positions:")
for start_pos in range(N - len(wtp) + 1):
    # Check if this overlaps with cribs
    overlaps_crib = False
    for crib_start, crib_text in [(21, ENE), (63, BC)]:
        if not (start_pos + len(wtp) <= crib_start or start_pos >= crib_start + len(crib_text)):
            overlaps_crib = True
            break

    # Compute key values at WTP positions
    key_at_wtp = [(CT_NUM[start_pos + i] - wtp_num[i]) % 26 for i in range(len(wtp))]
    key_text_at_wtp = ''.join(n2c(k) for k in key_at_wtp)

    # Check consistency with known crib-derived key
    crib_keys = {}
    for crib_start, crib_text in [(21, ENE), (63, BC)]:
        for i, ch in enumerate(crib_text):
            pos = crib_start + i
            crib_keys[pos] = (CT_NUM[pos] - c2n(ch)) % 26

    consistent = True
    for i in range(len(wtp)):
        pos = start_pos + i
        if pos in crib_keys:
            if key_at_wtp[i] != crib_keys[pos]:
                consistent = False
                break

    # Score key fragment for English-likeness
    qg_score = quadgram_score(key_text_at_wtp) if len(key_text_at_wtp) >= 4 else 0

    if not overlaps_crib:
        if qg_score > -100 or consistent:
            marker = " [crib-consistent]" if consistent else ""
            print(f"  pos={start_pos:2d}: key={key_text_at_wtp} qg={qg_score:.0f}{marker}")

# Also try other thematic phrases
print("\nTesting other phrases at non-crib positions:")
other_phrases = [
    'DELIVERTHEMESSAGE',
    'WHATSTHEPOINT',
    'NINETEENEIGHTYSIX',
    'NINETEENEIGHTYNINE',
    'THEWALLFELL',
    'FROMEGYPT',
    'FROMCAIRO',
    'MAGNETIC',
    'INVISIBLE',
    'UNDERGRUUND',
    'IQLUSION',
    'PALIMPSEST',
    'ABSCISSA',
    'BETWEEN',
    'SHADOW',
    'BURIED',
    'LANGLEY',
    'SLOWLY',
    'DESPERATELY',
    'LAYERTHREE',
    'LAYERFOUR',
]

best_phrase_results = []
for phrase in other_phrases:
    phrase_num = [c2n(c) for c in phrase]
    for start_pos in range(N - len(phrase) + 1):
        # Skip positions overlapping cribs
        overlaps = False
        for cs, ct in [(21, ENE), (63, BC)]:
            if not (start_pos + len(phrase) <= cs or start_pos >= cs + len(ct)):
                overlaps = True
                break
        if overlaps:
            continue

        key_frag = [(CT_NUM[start_pos + i] - phrase_num[i]) % 26 for i in range(len(phrase))]
        key_text = ''.join(n2c(k) for k in key_frag)
        qg = quadgram_score(key_text) if len(key_text) >= 4 else 0

        best_phrase_results.append((phrase, start_pos, key_text, qg))

best_phrase_results.sort(key=lambda x: x[3], reverse=True)
print("\nTop 20 phrase placements by key quadgram score:")
for phrase, pos, key_text, qg in best_phrase_results[:20]:
    print(f"  '{phrase}' at pos {pos}: key={key_text} qg={qg:.0f}")

# ============================================================
# WHAT IF THE KEY IS A KNOWN TEXT?
# ============================================================
print("\n" + "=" * 70)
print("KEY-AS-TEXT ANALYSIS")
print("=" * 70)
print("If the key IS English text, these are the forced key letters at crib positions:")
print()
key_at_cribs = {}
for crib_start, crib_text in [(21, ENE), (63, BC)]:
    for i, ch in enumerate(crib_text):
        pos = crib_start + i
        k = (CT_NUM[pos] - c2n(ch)) % 26
        key_at_cribs[pos] = n2c(k)

key_display = ['_'] * N
for pos, letter in key_at_cribs.items():
    key_display[pos] = letter

# Show the key with known positions
print("Pos: " + ''.join(f'{i%10}' for i in range(N)))
print("Key: " + ''.join(key_display))
print()
print(f"Known key at ENE (pos 21-33): {''.join(key_display[21:34])}")
print(f"Known key at BC  (pos 63-73): {''.join(key_display[63:74])}")
print()

# Check under Beaufort
print("Under Beaufort (key = CT + PT mod 26):")
beau_at_cribs = {}
for crib_start, crib_text in [(21, ENE), (63, BC)]:
    for i, ch in enumerate(crib_text):
        pos = crib_start + i
        k = (CT_NUM[pos] + c2n(ch)) % 26
        beau_at_cribs[pos] = n2c(k)

beau_display = ['_'] * N
for pos, letter in beau_at_cribs.items():
    beau_display[pos] = letter

print(f"Known key at ENE (pos 21-33): {''.join(beau_display[21:34])}")
print(f"Known key at BC  (pos 63-73): {''.join(beau_display[63:74])}")

# Under KA-Vigenere
print("\nUnder KA-Vigenere:")
KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
def ka_pos(c): return KA.index(c)
def ka_chr(n): return KA[n % 26]

ka_at_cribs = {}
for crib_start, crib_text in [(21, ENE), (63, BC)]:
    for i, ch in enumerate(crib_text):
        pos = crib_start + i
        k = (ka_pos(CT[pos]) - ka_pos(ch)) % 26
        ka_at_cribs[pos] = ka_chr(k)

ka_display = ['_'] * N
for pos, letter in ka_at_cribs.items():
    ka_display[pos] = letter

print(f"Known key at ENE (pos 21-33): {''.join(ka_display[21:34])}")
print(f"Known key at BC  (pos 63-73): {''.join(ka_display[63:74])}")

print("\n" + "=" * 70)
print("PLAINTEXT RECONSTRUCTION COMPLETE")
print("=" * 70)
