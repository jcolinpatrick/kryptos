#!/usr/bin/env python3
"""
Investigation 3: Massive Corpus Running Key Search (Model B Keystream)

Cipher: running_key_search
Family: analysis
Status: active
Keyspace: all reference texts + wordlists + auto-generated sequences
Last run:
Best score:

Under Model B (Beaufort on raw CT97, no transposition, no null extraction),
the key at 24 crib positions is known:

KEY[21..33] = J L J O D E G K U K K K L (13 chars)
KEY[63..73] = O C G G B G O K T R U (11 chars)

If the cipher uses a running key (key = passage from a text), then a 97-char
passage from some source text must contain these fragments at the right offsets.

The 13-char ENE key fragment "JLJODEGKUKKKL" is extremely distinctive:
- Contains "KKKK" (4 consecutive K's at key positions 28-32)
- Not English text (quadgram score ~ -7.6)

Search strategy:
1. Search all reference texts for exact/near matches of the key fragments
2. Search for the distinctive "KKKK" substring and check context
3. Search for other known key patterns (OCGGBGOKTRU from BCL)
4. Try the Kryptos tableau itself read in various orders
5. Try K1-K3 ciphertext and plaintext as running keys
6. Try the key fragment as the keyword for alphabet generation
7. Try XOR / modular combinations of known texts
"""

import sys, os, time, json, glob
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, ALPH, MOD

t0 = time.time()

# ── Constants ──────────────────────────────────────────────────────────────
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
N = len(CT)
I2N = {c: i for i, c in enumerate(AZ)}
N2L = {i: c for i, c in enumerate(AZ)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

ENE_START, ENE_TEXT = 21, "EASTNORTHEAST"
BCL_START, BCL_TEXT = 63, "BERLINCLOCK"
CT_NUMS = [I2N[c] for c in CT]

# Beaufort key at crib positions
PT_AT = {}
for i, ch in enumerate(ENE_TEXT):
    PT_AT[ENE_START + i] = ch
for i, ch in enumerate(BCL_TEXT):
    PT_AT[BCL_START + i] = ch

CRIB_POS = sorted(PT_AT.keys())
BEAU_KEY = {pos: (CT_NUMS[pos] + I2N[PT_AT[pos]]) % 26 for pos in CRIB_POS}
VIG_KEY = {pos: (CT_NUMS[pos] - I2N[PT_AT[pos]]) % 26 for pos in CRIB_POS}

# Key fragments as strings
ENE_KEY_BEAU = ''.join(N2L[BEAU_KEY[p]] for p in range(ENE_START, ENE_START + 13))
BCL_KEY_BEAU = ''.join(N2L[BEAU_KEY[p]] for p in range(BCL_START, BCL_START + 11))
ENE_KEY_VIG = ''.join(N2L[VIG_KEY[p]] for p in range(ENE_START, ENE_START + 13))
BCL_KEY_VIG = ''.join(N2L[VIG_KEY[p]] for p in range(BCL_START, BCL_START + 11))

# Full 97-char key (only known at 24 positions)
FULL_KEY_BEAU = ['?'] * N
for pos in CRIB_POS:
    FULL_KEY_BEAU[pos] = N2L[BEAU_KEY[pos]]

# Load quadgrams
QUADGRAMS = None
try:
    qg_path = "/home/cpatrick/kryptos/data/english_quadgrams.json"
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            QUADGRAMS = json.load(f)
        QG_FLOOR = min(QUADGRAMS.values()) - 1
except Exception:
    pass

def qg_score(text):
    if QUADGRAMS is None or len(text) < 4:
        return -99.0
    s = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return s / len(text)

print("=" * 80)
print("INVESTIGATION 3: Corpus Running Key Search (Model B Keystream)")
print("=" * 80)
print(f"CT: {CT}")
print(f"Beaufort key at ENE (pos 21-33): {ENE_KEY_BEAU}")
print(f"Beaufort key at BCL (pos 63-73): {BCL_KEY_BEAU}")
print(f"Vigenere key at ENE (pos 21-33): {ENE_KEY_VIG}")
print(f"Vigenere key at BCL (pos 63-73): {BCL_KEY_VIG}")
print(f"Full key (known): {''.join(FULL_KEY_BEAU)}")
print()

# Distinctive patterns in the key
# Beaufort: KKKK at positions 28-31 (key values 10,10,10,10)
# Also: OCGG at positions 63-66 (key), GG at 65-66, BGOK at 67-70
KKKK_PATTERN = "KKKK"
ENE_KEY = ENE_KEY_BEAU
BCL_KEY = BCL_KEY_BEAU

# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Search all reference text files
# ══════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("PHASE 1: Searching reference texts for key fragments")
print("=" * 80)

def sanitize(text):
    """Remove non-alpha chars, uppercase."""
    return ''.join(c.upper() for c in text if c.isalpha())

def search_text_for_fragment(text_alpha, fragment, max_mismatches=3):
    """Search for fragment in text, allowing up to max_mismatches differences.
    Returns list of (position, n_mismatches, context)."""
    results = []
    flen = len(fragment)
    for i in range(len(text_alpha) - flen + 1):
        window = text_alpha[i:i+flen]
        mismatches = sum(1 for a, b in zip(window, fragment) if a != b)
        if mismatches <= max_mismatches:
            # Context: 10 chars before and after
            start = max(0, i - 10)
            end = min(len(text_alpha), i + flen + 10)
            context = text_alpha[start:end]
            results.append((i, mismatches, window, context))
    return results

def search_text_for_kkkk(text_alpha):
    """Search for KKKK pattern."""
    results = []
    for i in range(len(text_alpha) - 3):
        if text_alpha[i:i+4] == "KKKK":
            start = max(0, i - 20)
            end = min(len(text_alpha), i + 24)
            context = text_alpha[start:end]
            results.append((i, context))
    return results

def check_full_key_match(text_alpha, offset):
    """Given a text and an offset (start of the 97-char key window),
    check how many of the 24 known key positions match."""
    if offset < 0 or offset + N > len(text_alpha):
        return 0, 0, 0
    window = text_alpha[offset:offset + N]
    ene_match = sum(1 for j in range(13) if window[ENE_START + j] == N2L[BEAU_KEY[ENE_START + j]])
    bcl_match = sum(1 for j in range(11) if window[BCL_START + j] == N2L[BEAU_KEY[BCL_START + j]])
    return ene_match + bcl_match, ene_match, bcl_match

# Collect all text sources
text_sources = {}

# Reference text files
ref_dir = "/home/cpatrick/kryptos/reference"
for ext in ['*.txt', '*.md']:
    for fpath in glob.glob(os.path.join(ref_dir, ext)):
        try:
            with open(fpath) as f:
                raw = f.read()
            text_sources[os.path.basename(fpath)] = sanitize(raw)
        except:
            pass

# Also try the full CT repeated / CT + KA + other strings
text_sources['CT97_repeated'] = sanitize(CT * 10)
text_sources['KA_repeated'] = sanitize(KA * 20)
text_sources['AZ_repeated'] = sanitize(AZ * 20)

# K1-K3 plaintexts (embedded)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROLAGE"  # approximate
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTH"  # approximate
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDGINGHOLETHELAMPELIGHTCANDLE"
text_sources['K1_PT'] = sanitize(K1_PT)
text_sources['K2_PT'] = sanitize(K2_PT)
text_sources['K3_PT'] = sanitize(K3_PT)
text_sources['K1K2K3_PT'] = sanitize(K1_PT + K2_PT + K3_PT)

# K1-K3 ciphertext
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"  # approximate fragment
K3_CT = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW"  # approximate
text_sources['K1_CT'] = sanitize(K1_CT)
text_sources['K3_CT'] = sanitize(K3_CT)
text_sources['K1K2K3_CT'] = sanitize(K1_CT + K2_CT + K3_CT)

# Kryptos tableau read in various orders
# Row by row (KA shifted by AZ index)
tableau_rows = []
for shift in range(26):
    row = ''.join(KA[(i + shift) % 26] for i in range(26))
    tableau_rows.append(row)
text_sources['tableau_rows'] = ''.join(tableau_rows)  # 676 chars

# Column by column
tableau_cols = []
for col in range(26):
    column = ''.join(KA[(col + shift) % 26] for shift in range(26))
    tableau_cols.append(column)
text_sources['tableau_cols'] = ''.join(tableau_cols)

# Diagonal reading
tableau_diag = ''.join(KA[(i + i) % 26] for i in range(26))
text_sources['tableau_diagonal'] = tableau_diag

# Spiral reading of tableau (simplified: read border then inner)
# Not trivial, skip for now

# Carter book text
try:
    for carter_file in ['carter_gutenberg.txt', 'carter_vol1.txt']:
        fpath = os.path.join(ref_dir, carter_file)
        if os.path.exists(fpath):
            with open(fpath) as f:
                raw = f.read()
            text_sources[carter_file] = sanitize(raw)
except:
    pass

# Master wordlist as continuous text
try:
    wl_path = "/home/cpatrick/kryptos/wordlists/english.txt"
    if os.path.exists(wl_path):
        with open(wl_path) as f:
            # Read first 100K words
            words = []
            for i, line in enumerate(f):
                if i >= 100000:
                    break
                words.append(line.strip().upper())
        text_sources['wordlist_concat'] = ''.join(w for w in words if w.isalpha())
except:
    pass

print(f"Loaded {len(text_sources)} text sources")
for name, text in sorted(text_sources.items()):
    print(f"  {name:30s}: {len(text)} chars")

# Search each source
print(f"\n--- Searching for ENE key fragment: {ENE_KEY} ---")
total_hits = 0
for name, text in sorted(text_sources.items()):
    hits = search_text_for_fragment(text, ENE_KEY, max_mismatches=3)
    if hits:
        for pos, mm, window, ctx in hits:
            total_hits += 1
            print(f"  {name}: pos={pos}, mismatches={mm}, window={window}")
            # Check if BCL fragment also matches at the right offset
            bcl_offset = pos + (BCL_START - ENE_START)
            if bcl_offset + 11 <= len(text):
                bcl_window = text[bcl_offset:bcl_offset + 11]
                bcl_mm = sum(1 for a, b in zip(bcl_window, BCL_KEY) if a != b)
                if bcl_mm <= 5:
                    print(f"    BCL at offset {bcl_offset}: {bcl_window} (mismatches={bcl_mm}) ***")
                    # Full 97-char check
                    key_offset = pos - ENE_START
                    total, ene, bcl_s = check_full_key_match(text, key_offset)
                    print(f"    Full 97-char key match: {total}/24 (ene={ene}, bcl={bcl_s})")

print(f"Total ENE fragment hits (<=3 mismatches): {total_hits}")

print(f"\n--- Searching for BCL key fragment: {BCL_KEY} ---")
total_hits_bcl = 0
for name, text in sorted(text_sources.items()):
    hits = search_text_for_fragment(text, BCL_KEY, max_mismatches=3)
    if hits:
        for pos, mm, window, ctx in hits:
            total_hits_bcl += 1
            print(f"  {name}: pos={pos}, mismatches={mm}, window={window}")

print(f"Total BCL fragment hits (<=3 mismatches): {total_hits_bcl}")

print(f"\n--- Searching for KKKK pattern ---")
for name, text in sorted(text_sources.items()):
    hits = search_text_for_kkkk(text)
    if hits:
        for pos, ctx in hits:
            print(f"  {name}: pos={pos}, context=...{ctx}...")
            # Check if this could be key positions 28-31
            key_offset = pos - 28
            if key_offset >= 0 and key_offset + N <= len(text):
                total, ene, bcl_s = check_full_key_match(text, key_offset)
                if total >= 6:
                    print(f"    Full 97-char key match at offset {key_offset}: {total}/24")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Vigenere variant search
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 2: Searching for Vigenere key fragments")
print("=" * 80)

print(f"Vigenere ENE key: {ENE_KEY_VIG}")
print(f"Vigenere BCL key: {BCL_KEY_VIG}")

for name, text in sorted(text_sources.items()):
    hits = search_text_for_fragment(text, ENE_KEY_VIG, max_mismatches=3)
    if hits:
        for pos, mm, window, ctx in hits:
            print(f"  {name}: pos={pos}, mismatches={mm}, window={window} (Vigenere ENE)")

for name, text in sorted(text_sources.items()):
    hits = search_text_for_fragment(text, BCL_KEY_VIG, max_mismatches=3)
    if hits:
        for pos, mm, window, ctx in hits:
            print(f"  {name}: pos={pos}, mismatches={mm}, window={window} (Vigenere BCL)")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Search with KA-indexed key values
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 3: KA-indexed key search")
print("=" * 80)

KA_IDX = {c: i for i, c in enumerate(KA)}
# Under KA-indexed Beaufort: K = (KA.index(CT) + KA.index(PT)) mod 26
ENE_KEY_KA_BEAU = ''.join(
    KA[(KA_IDX[CT[p]] + KA_IDX[PT_AT[p]]) % 26]
    for p in range(ENE_START, ENE_START + 13)
)
BCL_KEY_KA_BEAU = ''.join(
    KA[(KA_IDX[CT[p]] + KA_IDX[PT_AT[p]]) % 26]
    for p in range(BCL_START, BCL_START + 11)
)

print(f"KA-Beaufort ENE key: {ENE_KEY_KA_BEAU}")
print(f"KA-Beaufort BCL key: {BCL_KEY_KA_BEAU}")

for name, text in sorted(text_sources.items()):
    hits = search_text_for_fragment(text, ENE_KEY_KA_BEAU, max_mismatches=3)
    if hits:
        for pos, mm, window, ctx in hits:
            print(f"  {name}: pos={pos}, mismatches={mm}, window={window} (KA-Beau ENE)")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Sliding window full-key match across all texts
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 4: Sliding window full 24-position key match")
print("=" * 80)

for name, text in sorted(text_sources.items()):
    if len(text) < N:
        continue
    best_match = 0
    best_offset = 0
    for offset in range(len(text) - N + 1):
        total, ene, bcl_s = check_full_key_match(text, offset)
        if total > best_match:
            best_match = total
            best_offset = offset
    if best_match >= 5:
        print(f"  {name:30s}: best {best_match}/24 at offset {best_offset}")
        window = text[best_offset:best_offset + N]
        print(f"    Key window: {window}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Modular combinations of known texts
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 5: Modular combinations of text pairs as running key")
print("=" * 80)

# Try: key = (text_A[i] + text_B[i]) mod 26, or (text_A[i] - text_B[i]) mod 26
# where text_A and text_B are different sources

# Use shorter texts for this
short_sources = {k: v for k, v in text_sources.items() if 97 <= len(v) <= 10000}

combos_tested = 0
best_combo_score = 0
best_combo_info = ""

for name_a, text_a in sorted(short_sources.items()):
    for name_b, text_b in sorted(short_sources.items()):
        if name_a >= name_b:
            continue  # Avoid duplicates

        max_len = min(len(text_a), len(text_b))
        if max_len < N:
            continue

        for op_name, op_func in [
            ("add", lambda a, b: (a + b) % 26),
            ("sub", lambda a, b: (a - b) % 26),
        ]:
            for off_a in range(0, min(max_len - N + 1, 100)):
                for off_b in range(0, min(max_len - N + 1, 100)):
                    # Compute combined key
                    combined = []
                    for i in range(N):
                        if off_a + i >= len(text_a) or off_b + i >= len(text_b):
                            break
                        a_val = I2N.get(text_a[off_a + i], 0)
                        b_val = I2N.get(text_b[off_b + i], 0)
                        combined.append(op_func(a_val, b_val))

                    if len(combined) < N:
                        continue

                    # Check against known key values
                    ene_match = sum(1 for j in range(13) if combined[ENE_START + j] == BEAU_KEY[ENE_START + j])
                    bcl_match = sum(1 for j in range(11) if combined[BCL_START + j] == BEAU_KEY[BCL_START + j])
                    total = ene_match + bcl_match
                    combos_tested += 1

                    if total > best_combo_score:
                        best_combo_score = total
                        best_combo_info = f"{name_a}[{off_a}] {op_name} {name_b}[{off_b}]: {total}/24 (ene={ene_match}, bcl={bcl_match})"

                    if total >= 8:
                        key_str = ''.join(N2L[v] for v in combined[:N])
                        print(f"  {name_a}[{off_a}] {op_name} {name_b}[{off_b}]: {total}/24 "
                              f"(ene={ene_match}, bcl={bcl_match})")

print(f"Tested {combos_tested} text combinations")
print(f"Best: {best_combo_info}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 6: Tableau-derived key sequences
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 6: Tableau-derived key sequences")
print("=" * 80)

# Read the KA tableau in various ways and check as running key
# Row r, column c: KA[(c + r) % 26] where r = AZ.index(key_letter)

# Try: key[i] = tableau[row(i), col(i)] for various row/col mappings
# Row from AZ (row 0=A, row 1=B, ...), column from position

# Model: key[i] = KA[ (i + something) % 26 ]
# This is equivalent to shifting KA by i -- a very simple running key from the tableau itself

for start_row in range(26):
    for start_col in range(26):
        # Read tableau starting at (start_row, start_col), going right then down
        key = []
        for i in range(N):
            row = (start_row + (start_col + i) // 26) % 26
            col = (start_col + i) % 26
            key.append((row + col) % 26)  # KA index = (row_shift + col) % 26
            # But the actual tableau cell: KA[(AZ.index(left_col_letter) + KA_header_position) % 26]
            # Since left column is AZ: row_shift = start_row + row_within
            # header position = start_col + i % 26

        # Check against known key values
        ene_match = sum(1 for j in range(13) if key[ENE_START + j] == BEAU_KEY[ENE_START + j])
        bcl_match = sum(1 for j in range(11) if key[BCL_START + j] == BEAU_KEY[BCL_START + j])
        total = ene_match + bcl_match
        if total >= 6:
            key_str = ''.join(KA[k] for k in key[:N])
            print(f"  start=({start_row},{start_col}): {total}/24 (ene={ene_match}, bcl={bcl_match})")

# Also try: column-major reading
for start_row in range(26):
    for start_col in range(26):
        key = []
        for i in range(N):
            col = (start_col + i // 26) % 26
            row = (start_row + i % 26) % 26
            key.append((row + col) % 26)

        ene_match = sum(1 for j in range(13) if key[ENE_START + j] == BEAU_KEY[ENE_START + j])
        bcl_match = sum(1 for j in range(11) if key[BCL_START + j] == BEAU_KEY[BCL_START + j])
        total = ene_match + bcl_match
        if total >= 6:
            print(f"  col-major start=({start_row},{start_col}): {total}/24")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 7: Key fragment as cipher keyword
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 7: Key fragments as cipher keywords")
print("=" * 80)

# Use the key fragments themselves as keywords for mixed alphabets
# Then check if a simple period or autokey works

from kryptos.kernel.alphabet import keyword_mixed_alphabet

key_keywords = [
    ENE_KEY_BEAU,  # JLJODEGKUKKKL
    BCL_KEY_BEAU,  # OCGGBGOKTRU
    ENE_KEY_BEAU + BCL_KEY_BEAU,  # Combined
    "KKKK",        # Distinctive 4-K pattern
    "GKO",         # AP triple
    "GKOK",        # AP + K
]

for kw in key_keywords:
    alpha = keyword_mixed_alphabet(kw)
    alpha_idx = {c: i for i, c in enumerate(alpha)}

    # Check period-13 under this alphabet
    from collections import Counter
    for period in [7, 13, 26]:
        residue_keys = defaultdict(set)
        for pos in CRIB_POS:
            r = pos % period
            ct_idx = alpha_idx[CT[pos]]
            pt_idx = alpha_idx[PT_AT[pos]]
            # Beaufort
            k = (ct_idx + pt_idx) % 26
            residue_keys[r].add(k)

        n_conflict = sum(1 for v in residue_keys.values() if len(v) > 1)
        n_match = sum(max(Counter(k for k in v).values()) for v in residue_keys.values())

        if n_conflict == 0:
            key_letters = []
            for r in range(period):
                if r in residue_keys:
                    key_letters.append(alpha[list(residue_keys[r])[0]])
                else:
                    key_letters.append('?')
            print(f"  kw={kw:20s} alpha_prefix={alpha[:10]}... p={period}: CONSISTENT, "
                  f"key={''.join(key_letters)}")

            # Decrypt and score
            pt = []
            for i in range(N):
                r = i % period
                ct_val = alpha_idx[CT[i]]
                if r in residue_keys and len(residue_keys[r]) == 1:
                    k = list(residue_keys[r])[0]
                else:
                    k = 0
                pt_val = (k - ct_val) % 26
                pt.append(alpha[pt_val])
            pt_text = ''.join(pt)
            qg = qg_score(pt_text)
            print(f"    PT: {pt_text[:60]}... qg={qg:.4f}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 8: Extended reference corpus search
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 8: Extended corpus search (Carter volumes)")
print("=" * 80)

# Focus on Carter texts which are the most promising reference source
for carter_file in ['carter_gutenberg.txt', 'carter_vol1.txt']:
    fpath = os.path.join(ref_dir, carter_file)
    if not os.path.exists(fpath):
        continue

    with open(fpath) as f:
        raw = f.read()
    text = sanitize(raw)

    print(f"\n  {carter_file}: {len(text)} alpha chars")

    # Search for all 4+ char substrings of the ENE key
    for frag_len in range(4, 14):
        for start in range(14 - frag_len):
            fragment = ENE_KEY_BEAU[start:start + frag_len]
            hits = search_text_for_fragment(text, fragment, max_mismatches=0)
            if hits:
                for pos, mm, window, ctx in hits:
                    # Check if extending to full key matches
                    key_start_in_text = pos - (ENE_START + start)
                    if 0 <= key_start_in_text and key_start_in_text + N <= len(text):
                        total, ene, bcl_s = check_full_key_match(text, key_start_in_text)
                        if total >= 8:
                            print(f"    Found '{fragment}' at {pos}, full match: {total}/24")

    # Search for BCL key substrings
    for frag_len in range(4, 12):
        for start in range(12 - frag_len):
            fragment = BCL_KEY_BEAU[start:start + frag_len]
            hits = search_text_for_fragment(text, fragment, max_mismatches=0)
            if hits:
                for pos, mm, window, ctx in hits:
                    key_start_in_text = pos - (BCL_START + start)
                    if 0 <= key_start_in_text and key_start_in_text + N <= len(text):
                        total, ene, bcl_s = check_full_key_match(text, key_start_in_text)
                        if total >= 8:
                            print(f"    Found '{fragment}' at {pos}, full match: {total}/24")

    # Brute force: check every possible 97-char window
    best_match = 0
    best_offset = 0
    for offset in range(len(text) - N + 1):
        total, ene, bcl_s = check_full_key_match(text, offset)
        if total > best_match:
            best_match = total
            best_offset = offset
    print(f"    Best sliding window match: {best_match}/24 at offset {best_offset}")
    if best_match >= 5:
        window = text[best_offset:best_offset + N]
        print(f"    Window: {window}")
        # Decrypt with this window as key
        pt = []
        for i in range(N):
            k = I2N[window[i]]
            ct_val = CT_NUMS[i]
            pt_val = (k - ct_val) % 26
            pt.append(N2L[pt_val])
        pt_text = ''.join(pt)
        print(f"    Decrypted PT: {pt_text}")
        qg = qg_score(pt_text)
        print(f"    Quadgram: {qg:.4f}")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 9: Transcript and meeting notes search
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 9: Transcript/document search")
print("=" * 80)

# Try to load any readable reference documents
for fname in os.listdir(ref_dir):
    fpath = os.path.join(ref_dir, fname)
    if not os.path.isfile(fpath):
        continue
    if fname.endswith(('.txt', '.md')):
        try:
            with open(fpath) as f:
                raw = f.read()
            text = sanitize(raw)
            if len(text) >= N:
                best_match = 0
                for offset in range(len(text) - N + 1):
                    total, ene, bcl_s = check_full_key_match(text, offset)
                    if total > best_match:
                        best_match = total
                if best_match >= 5:
                    print(f"  {fname}: best {best_match}/24")
        except:
            pass

# ── Summary ───────────────────────────────────────────────────────────────
elapsed = time.time() - t0
print("\n" + "=" * 80)
print(f"INVESTIGATION 3 COMPLETE ({elapsed:.1f}s)")
print("=" * 80)

print(f"""
SUMMARY:
- Searched {len(text_sources)} text sources for Beaufort key fragments
- ENE key fragment: {ENE_KEY_BEAU} (13 chars)
- BCL key fragment: {BCL_KEY_BEAU} (11 chars)
- Distinctive pattern: KKKK (4 consecutive K's in key)
- Also searched Vigenere and KA-indexed variants
- Tested modular combinations of text pairs
- Tested tableau-derived key sequences
- Tested key fragments as cipher keywords
""")

# Save results
results = {
    'experiment': 'CORPUS_KEYSTREAM_SEARCH',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
    'elapsed_seconds': elapsed,
    'ene_key_beau': ENE_KEY_BEAU,
    'bcl_key_beau': BCL_KEY_BEAU,
    'ene_key_vig': ENE_KEY_VIG,
    'bcl_key_vig': BCL_KEY_VIG,
    'sources_searched': len(text_sources),
}

out_path = '/home/cpatrick/kryptos/results/corpus_keystream_search.json'
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"Results saved to: {out_path}")
