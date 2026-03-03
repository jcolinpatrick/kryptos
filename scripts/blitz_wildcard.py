#!/usr/bin/env python3
"""
blitz_wildcard.py — Lateral & Creative Approaches to K4 Unscrambling
=====================================================================
MISSION: Find the permutation that maps carved K4 text → real ciphertext
         Then: PT = Vigenère/Beaufort decrypt with short keyword

Paradigm: PT → simple substitution → REAL_CT → SCRAMBLE → K4 (carved)
          Unscrambling: real_CT[i] = K4[perm[i]]  for some unknown perm

Approaches:
A. Interleaved streams (split into k=2..7 streams, test each independently)
B. Grille extract arithmetic ops (mod-26 difference, XOR) vs K4
C. Self-referential permutation (K4 defines its own reading order via char values)
D. K1-K3 ciphertext / plaintext as the scrambling key
E. Copper plate fold permutations (various fold points)
F. Grille extract as substitution alphabet → first-occurrence reading order
G. Column-order and row-skip paths through grille holes
H. Clock cipher (Weltzeituhr: groups of 24, 11-segment clock arithmetic)
I. Positional encoding via T-absence / K4 letter categories
J. IDBYROWS — keyword-ordered column reading of K4 in various-width grids
K. Doubled-letter position encoding (K4's many doubles as structural signal)
L. KA-index mapping → permutation (char values in KA alphabet)
M. Reversed-group permutations (k groups reversed in various orderings)
N. Known-keyword reverse engineering (assume keyword → derive required perm)
O. Plateau / flat-region transpositions (density-based partitioning)

Run as: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_wildcard.py
"""

import sys, json, math, os, time, random, itertools
from collections import Counter, defaultdict
from itertools import permutations as iperm

sys.path.insert(0, 'src')

# ── Constants ────────────────────────────────────────────────────────────────

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(K4)
assert N == 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GRILLE_EXTRACT) == 106
assert 'T' not in GRILLE_EXTRACT

KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
    'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA',
    'ENIGMA', 'COMPASS', 'WELTZEITUHR', 'IQLUSION', 'ILLUSION', 'LAYER',
    'DIGETAL', 'FLANKMAN', 'VIRTUALLY', 'SHADOW', 'FORCES', 'INVISIBLE',
]
# Deduplicate
KEYWORDS = list(dict.fromkeys(KEYWORDS))

CRIB_ENE = "EASTNORTHEAST"   # 13 chars
CRIB_BC  = "BERLINCLOCK"     # 11 chars

# K1 ciphertext (63 chars)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
# K3 ciphertext (approx 336 chars)
K3_CT = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLLSLKNQIORAATOYETWQRXTQRSKSPTQUMWKFLRUQISASXDGMMJKJDMQICQTGLKZUGYSYQXQKOFYPJXZHQKTAYGCUEOGXIXEFGIUZEJTQHNZ"
# K1+K3 plaintext snippets
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K3_PT = "SLOWLYDESPERATELYSLOWTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGSHANDSMADEATINYBREACHINTHUPPERLEFTHANDCORNERANDTHENWIDENIENGTHEM"

# ── Authoritative grille mask (space-separated, 0=hole, 1=masked, ~=off-grid) ─
MASK_TEXT = """\
1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    ~
0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    1    1    0    1    1    1    1    0    0    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    1    0    ~    ~
1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    0    0    1    0    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    0    ~
1    1    1    1    0    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    ~    ~
1    1    0    1    1    0    1    1    1    1    0    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    0    1    ~    ~
1    1    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    0    1    1    0    1    1    0    ~    ~
1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    0    1    1    0    1    1    0    1    1    ~
1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    0    1    1
0    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    0    ~    ~
1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    ~    ~"""

# Parse mask: 0=hole, 1=masked, ~=off-grid
HOLES = []  # (row, col) 0-indexed
for r, line in enumerate(MASK_TEXT.strip().split('\n')):
    vals = line.split()
    for c, v in enumerate(vals):
        if v == '~':
            continue
        if v == '0':
            HOLES.append((r, c))

print(f"Parsed {len(HOLES)} holes from mask (expected 107)", flush=True)
assert len(HOLES) == 107, f"Expected 107 holes, got {len(HOLES)}"

# ── Quadgrams ────────────────────────────────────────────────────────────────
print("Loading quadgrams...", flush=True)
QG = json.load(open('data/english_quadgrams.json'))
MISS = min(QG.values()) - 2.0

def qscore(text):
    n = len(text)
    if n < 4: return MISS
    return sum(QG.get(text[i:i+4], MISS) for i in range(n-3)) / (n-3)

print(f"  {len(QG)} quadgrams loaded, MISS={MISS:.2f}", flush=True)

# ── Alphabet index maps ──────────────────────────────────────────────────────
AZI = {c: i for i, c in enumerate(AZ)}
KAI = {c: i for i, c in enumerate(KA)}

# ── Output setup ─────────────────────────────────────────────────────────────
os.makedirs('blitz_results/wildcard', exist_ok=True)
RESULTS_FILE = 'blitz_results/wildcard/results.jsonl'
_rf = open(RESULTS_FILE, 'a')
HITS = []

def save_result(d):
    _rf.write(json.dumps(d) + '\n')
    _rf.flush()

# ── Core cipher functions ────────────────────────────────────────────────────
def vig_dec(ct, key, alpha=AZ, ai=None):
    if ai is None: ai = {c: i for i, c in enumerate(alpha)}
    n = len(alpha)
    ki = [ai.get(c, 0) for c in key]
    if not ki: return ct
    return ''.join(alpha[(ai.get(ct[i], 0) - ki[i % len(ki)]) % n] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ, ai=None):
    if ai is None: ai = {c: i for i, c in enumerate(alpha)}
    n = len(alpha)
    ki = [ai.get(c, 0) for c in key]
    if not ki: return ct
    return ''.join(alpha[(ki[i % len(ki)] - ai.get(ct[i], 0)) % n] for i in range(len(ct)))

CIPHERS = [
    ("vig_AZ",  lambda ct, kw: vig_dec(ct, kw, AZ, AZI)),
    ("beau_AZ", lambda ct, kw: beau_dec(ct, kw, AZ, AZI)),
    ("vig_KA",  lambda ct, kw: vig_dec(ct, kw, KA, KAI)),
    ("beau_KA", lambda ct, kw: beau_dec(ct, kw, KA, KAI)),
]

# ── Permutation utilities ─────────────────────────────────────────────────────
def validate_perm(perm):
    return len(perm) == N and sorted(perm) == list(range(N))

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

def argsort(seq):
    """Return indices that would sort seq (stable)."""
    return sorted(range(len(seq)), key=lambda i: (seq[i], i))

def rank_of(seq):
    """Return rank of each element (0-indexed, stable)."""
    s = argsort(seq)
    r = [0] * len(seq)
    for rank, idx in enumerate(s):
        r[idx] = rank
    return r

# ── Crib search ──────────────────────────────────────────────────────────────
_tested = set()
total_tested = 0

def test_ct(candidate_ct, label):
    """Test a candidate CT (already permuted) against all keywords/ciphers."""
    global total_tested
    key = candidate_ct
    if key in _tested:
        return None
    _tested.add(key)
    total_tested += 1

    best_score = MISS - 1
    best = None
    for kw in KEYWORDS:
        for cname, cfn in CIPHERS:
            pt = cfn(candidate_ct, kw)
            ene = pt.find(CRIB_ENE)
            bc  = pt.find(CRIB_BC)
            if ene >= 0 or bc >= 0:
                sc = qscore(pt)
                msg = (f"*** CRIB HIT [{label}]: ENE@{ene} BC@{bc} "
                       f"key={kw} cipher={cname} score={sc:.3f}")
                print(msg, flush=True)
                print(f"    candidate_CT: {candidate_ct}", flush=True)
                print(f"    PT:           {pt}", flush=True)
                d = {'label': label, 'ct': candidate_ct, 'key': kw,
                     'cipher': cname, 'ene': ene, 'bc': bc, 'pt': pt, 'score': sc}
                HITS.append(d)
                save_result(d)
                return d
            sc = qscore(pt)
            if sc > best_score:
                best_score = sc
                best = {'label': label, 'ct': candidate_ct, 'key': kw,
                        'cipher': cname, 'ene': -1, 'bc': -1, 'pt': pt, 'score': sc}
    if best and best['score'] > -7.0:
        save_result(best)
    return best

def test_perm(perm, label):
    """Apply permutation then test."""
    if not validate_perm(perm):
        return None
    return test_ct(apply_perm(K4, perm), label)

def report_best(results, approach_name):
    valid = [r for r in results if r is not None]
    if not valid:
        print(f"  [{approach_name}] No results", flush=True)
        return
    best = max(valid, key=lambda r: r.get('score', MISS))
    hit = next((r for r in valid if r.get('ene', -1) >= 0 or r.get('bc', -1) >= 0), None)
    if hit:
        print(f"  [{approach_name}] *** CRIB HIT: {hit['label']} score={hit['score']:.3f}", flush=True)
    else:
        print(f"  [{approach_name}] Best: label={best['label']} key={best['key']} cipher={best['cipher']} score={best['score']:.3f}", flush=True)
        print(f"               PT: {best['pt']}", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH A: INTERLEAVED STREAMS
# ─────────────────────────────────────────────────────────────────────────────
def approach_A():
    print("\n" + "="*70, flush=True)
    print("APPROACH A: INTERLEAVED STREAMS", flush=True)
    print("="*70, flush=True)
    results = []

    for k in range(2, 8):
        # Split K4 into k interleaved streams
        streams = [K4[i::k] for i in range(k)]
        print(f"  k={k}: stream lengths={[len(s) for s in streams]}", flush=True)

        # A1: Test each stream independently as a CT fragment
        for si, stream in enumerate(streams):
            if len(stream) < 4:
                continue
            for kw in KEYWORDS:
                for cname, cfn in CIPHERS:
                    pt = cfn(stream, kw)
                    for crib in [CRIB_ENE, CRIB_BC]:
                        if crib in pt:
                            sc = qscore(pt)
                            label = f"A_stream_k{k}s{si}_{kw}_{cname}"
                            print(f"  *** STREAM CRIB [{label}]: crib found! score={sc:.3f}", flush=True)
                            print(f"      stream: {stream}", flush=True)
                            print(f"      pt:     {pt}", flush=True)
                            d = {'label': label, 'stream': stream, 'key': kw,
                                 'cipher': cname, 'crib': crib, 'pt': pt, 'score': sc}
                            HITS.append(d); save_result(d)

        # A2: All permutations of stream order → recombine → try as CT
        if k <= 5:
            for stream_order in iperm(range(k)):
                # Interleave streams in given order
                max_len = max(len(s) for s in streams)
                chars = []
                for pos in range(max_len):
                    for si in stream_order:
                        if pos < len(streams[si]):
                            chars.append(streams[si][pos])
                candidate_ct = ''.join(chars[:97])
                if len(candidate_ct) == 97:
                    label = f"A_reorder_k{k}_{''.join(map(str,stream_order))}"
                    r = test_ct(candidate_ct, label)
                    results.append(r)

        # A3: Concatenate streams in all orders → treat as permuted CT
        if k <= 5:
            for stream_order in iperm(range(k)):
                concat = ''.join(streams[si] for si in stream_order)[:97]
                if len(concat) == 97:
                    label = f"A_concat_k{k}_{''.join(map(str,stream_order))}"
                    r = test_ct(concat, label)
                    results.append(r)

    report_best(results, "A")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH B: GRILLE EXTRACT ARITHMETIC vs K4
# ─────────────────────────────────────────────────────────────────────────────
def approach_B():
    print("\n" + "="*70, flush=True)
    print("APPROACH B: GRILLE EXTRACT ARITHMETIC vs K4", flush=True)
    print("="*70, flush=True)
    results = []

    G97 = GRILLE_EXTRACT[:97]   # first 97 chars
    G97_9 = GRILLE_EXTRACT[9:]  # skip first 9 → length 97

    for g_label, g_text in [("G97_first", G97), ("G97_skip9", G97_9)]:
        assert len(g_text) == 97, f"Bad length for {g_label}"
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            n = len(alpha)
            gv = [ai.get(c, 0) for c in g_text]
            kv = [ai.get(c, 0) for c in K4]

            # B1: (G[i] - K4[i]) mod 26 → as potential plaintext
            diff1 = ''.join(alpha[(gv[i] - kv[i]) % n] for i in range(97))
            r = test_ct(diff1, f"B_G-K4_{g_label}_{alpha_name}")
            results.append(r)

            # B2: (K4[i] - G[i]) mod 26 → as potential plaintext
            diff2 = ''.join(alpha[(kv[i] - gv[i]) % n] for i in range(97))
            r = test_ct(diff2, f"B_K4-G_{g_label}_{alpha_name}")
            results.append(r)

            # B3: (G[i] + K4[i]) mod 26 → as potential plaintext (G as Beaufort)
            sum1 = ''.join(alpha[(gv[i] + kv[i]) % n] for i in range(97))
            r = test_ct(sum1, f"B_G+K4_{g_label}_{alpha_name}")
            results.append(r)

            # B4: Treat G as running key → G[i] XOR K4[i] (bitwise mod 26)
            xor1 = ''.join(alpha[(gv[i] ^ kv[i]) % n] for i in range(97))
            r = test_ct(xor1, f"B_XOR_{g_label}_{alpha_name}")
            results.append(r)

            # B5: rank of (G-K4 differences) as permutation
            diffs_raw = [(gv[i] - kv[i]) % n for i in range(97)]
            perm_B5 = argsort(diffs_raw)
            r = test_perm(perm_B5, f"B_rank_diff_{g_label}_{alpha_name}")
            results.append(r)

            # B6: inverse of B5
            inv_B5 = [0]*97
            for idx, p in enumerate(perm_B5):
                inv_B5[p] = idx
            r = test_perm(inv_B5, f"B_inv_rank_diff_{g_label}_{alpha_name}")
            results.append(r)

    # B7: Use extract mod 97 (cyclic index) as permutation seed
    # Each extract letter → its KA index, scale to 0-96 range
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        n = len(alpha)
        # Scale: pos_in_97 = (letter_index * 97) // 26
        scaled = [(ai.get(GRILLE_EXTRACT[i], 0) * 97) // n for i in range(106)]
        # Build permutation from first 97 scaled values (if valid)
        used = set()
        perm_B7 = []
        for v in scaled:
            if v not in used and v < 97:
                perm_B7.append(v)
                used.add(v)
            if len(perm_B7) == 97:
                break
        # Fill remaining
        for v in range(97):
            if v not in used:
                perm_B7.append(v)
                used.add(v)
        if validate_perm(perm_B7):
            r = test_perm(perm_B7, f"B_scaled_mod97_{alpha_name}")
            results.append(r)

    report_best(results, "B")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH C: SELF-REFERENTIAL PERMUTATION
# ─────────────────────────────────────────────────────────────────────────────
def approach_C():
    print("\n" + "="*70, flush=True)
    print("APPROACH C: SELF-REFERENTIAL PERMUTATION", flush=True)
    print("="*70, flush=True)
    results = []

    # C1: rank permutation of K4 itself (argsort)
    # perm[i] = where K4[i] would go in sorted order
    perm_C1 = argsort(K4)   # sorted(K4)[rank[i]] = K4[i]
    r = test_perm(perm_C1, "C_argsort_K4")
    results.append(r)

    # C2: inverse of C1
    inv_C1 = [0]*97
    for idx, p in enumerate(perm_C1):
        inv_C1[p] = idx
    r = test_perm(inv_C1, "C_inv_argsort_K4")
    results.append(r)

    # C3: K4 character values as indices mod 97
    # K4[i]='O'=14 → if we scale: position i → position (14 * 97 // 26)
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        n = len(alpha)
        # Scale method 1: multiply by 97//26 ≈ 3.73
        raw = [(ai.get(K4[i], 0) * 97 + i) % 97 for i in range(97)]
        perm_C3 = argsort(raw)
        r = test_perm(perm_C3, f"C_scaled_alpha_{alpha_name}")
        results.append(r)

    # C4: Cycle following — start at pos 0, next = AZ.index(K4[current]) mod 97
    # This creates a traversal of K4's positions
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        n = len(alpha)
        for scale in [4, 1, 97]:  # different scaling factors
            visited = [False] * 97
            order = []
            pos = 0
            safety = 0
            while len(order) < 97 and safety < 97 * 97:
                safety += 1
                if not visited[pos]:
                    order.append(pos)
                    visited[pos] = True
                next_pos = (ai.get(K4[pos], 0) * scale) % 97
                if next_pos == pos or visited[next_pos]:
                    # Jump to first unvisited
                    found = False
                    for p in range(97):
                        if not visited[p]:
                            next_pos = p
                            found = True
                            break
                    if not found:
                        break
                pos = next_pos
            if len(order) == 97 and validate_perm(order):
                r = test_perm(order, f"C_cycle_{alpha_name}_scale{scale}")
                results.append(r)

    # C5: K4 consecutive character differences as permutation seed
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        n = len(alpha)
        diffs = [(ai.get(K4[i+1], 0) - ai.get(K4[i], 0)) % n for i in range(96)]
        diffs.append(0)  # last position
        perm_C5 = argsort([(d, i) for i, d in enumerate(diffs)])
        if validate_perm(perm_C5):
            r = test_perm(perm_C5, f"C_consecutive_diff_{alpha_name}")
            results.append(r)

    # C6: K4 iterated through its own permutation (apply perm_C1 repeatedly)
    current_ct = K4
    for iteration in range(1, 50):
        current_ct = apply_perm(current_ct, perm_C1)
        r = test_ct(current_ct, f"C_iterate_argsort_{iteration}")
        results.append(r)
        if iteration % 10 == 0:
            print(f"  C6: iteration {iteration}", flush=True)

    report_best(results, "C")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH D: K1-K3 CIPHERTEXT/PLAINTEXT AS SCRAMBLING KEY
# ─────────────────────────────────────────────────────────────────────────────
def approach_D():
    print("\n" + "="*70, flush=True)
    print("APPROACH D: K1-K3 AS SCRAMBLING KEY", flush=True)
    print("="*70, flush=True)
    results = []

    texts = [
        ("K1_CT", K1_CT),
        ("K3_CT", K3_CT),
        ("K1_PT", K1_PT),
        ("K3_PT", K3_PT),
        ("K1CT+K3CT", K1_CT + K3_CT),
        ("K3CT_rev", K3_CT[::-1]),
        ("K1CT_rev", K1_CT[::-1]),
    ]

    for tname, text in texts:
        # Use first 97 chars if available, else pad/wrap
        t97 = (text * 2)[:97]
        assert len(t97) == 97

        # D1: rank-order of text as permutation (columnar key)
        perm_D1 = argsort(t97)
        r = test_perm(perm_D1, f"D_argsort_{tname}")
        results.append(r)

        # D2: inverse
        inv_D1 = [0]*97
        for idx, p in enumerate(perm_D1):
            inv_D1[p] = idx
        r = test_perm(inv_D1, f"D_inv_argsort_{tname}")
        results.append(r)

        # D3: AZ-position-weighted rank
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            weighted = [(ai.get(t97[i], 0), i) for i in range(97)]
            perm_D3 = [w[1] for w in sorted(weighted)]
            if validate_perm(perm_D3):
                r = test_perm(perm_D3, f"D_weighted_{tname}_{alpha_name}")
                results.append(r)

        # D4: columnar transposition using text as key (widths 7-20)
        for width in range(7, 21):
            # Build column order from keyword
            key_part = t97[:width]
            col_order = argsort(key_part)

            # Read columns in key-order
            nrows = math.ceil(97 / width)
            # Pad to exact grid size
            padded = K4 + 'X' * (nrows * width - 97)
            grid = [padded[r*width:(r+1)*width] for r in range(nrows)]
            candidate_ct = ''.join(grid[r][c] for c in col_order for r in range(nrows)
                                   if r*width + c < 97 + (nrows*width - 97))
            candidate_ct = ''.join(c for c in candidate_ct if c in AZ)[:97]
            if len(candidate_ct) == 97:
                r = test_ct(candidate_ct, f"D_col_w{width}_{tname}")
                results.append(r)

    report_best(results, "D")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH E: COPPER PLATE FOLD PERMUTATIONS
# ─────────────────────────────────────────────────────────────────────────────
def approach_E():
    print("\n" + "="*70, flush=True)
    print("APPROACH E: COPPER PLATE FOLD PERMUTATIONS", flush=True)
    print("="*70, flush=True)
    results = []

    # E1: Simple fold at various points
    # Fold at position k: chars 0..k-1 stay, chars k..96 are reversed and interleaved
    for k in range(1, 97):
        front = list(range(k))          # positions 0..k-1
        back  = list(range(96, k-1, -1))  # positions 96..k (reversed)
        # Interleave front and back
        max_len = max(len(front), len(back))
        interleaved = []
        for i in range(max_len):
            if i < len(front):
                interleaved.append(front[i])
            if i < len(back):
                interleaved.append(back[i])
        perm = interleaved[:97]
        if len(perm) == 97 and validate_perm(perm):
            r = test_perm(perm, f"E_fold_interleave_k{k}")
            results.append(r)

        # Fold: read front then reversed back
        perm2 = front + back
        if len(perm2) == 97 and validate_perm(perm2):
            r = test_perm(perm2, f"E_fold_concat_k{k}")
            results.append(r)

    # E2: Fold and overlay (front[i] maps to back[i])
    # For fold at midpoint: position i ↔ position (N-1-i)
    # Read as: even positions from front half, odd from back half
    for k in [48, 49, 50]:
        half1 = list(range(k))
        half2 = list(range(96, 96-k, -1))
        # Weave: alternately take from half1 and half2
        perm = []
        for i in range(min(len(half1), len(half2))):
            perm.append(half1[i])
            perm.append(half2[i])
        # Add remaining
        if len(half1) > len(half2):
            perm.extend(half1[len(half2):])
        elif len(half2) > len(half1):
            perm.extend(half2[len(half1):])
        perm = perm[:97]
        if len(perm) == 97 and validate_perm(perm):
            r = test_perm(perm, f"E_fold_weave_k{k}")
            results.append(r)

    # E3: "8 Lines 73" fold — 8 rows × ~12 chars, special reading
    # From kryptosfan: "8 Lines 73" is a K4 layout hint
    for width in [8, 9, 10, 11, 12, 13]:
        nrows = math.ceil(97 / width)
        for fold_row in range(1, nrows):
            # Fold at fold_row: rows 0..fold_row-1 normal, rows fold_row..nrows-1 reversed
            top_positions = list(range(fold_row * width))[:97]
            bottom = []
            for r in range(nrows-1, fold_row-1, -1):
                for c in range(width):
                    pos = r * width + c
                    if pos < 97:
                        bottom.append(pos)
            perm = (top_positions + bottom)[:97]
            if len(set(perm)) == 97 and validate_perm(perm):
                r = test_perm(perm, f"E_8lines_w{width}_fold{fold_row}")
                results.append(r)

    report_best(results, "E")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH F: GRILLE EXTRACT AS SUBSTITUTION ALPHABET → READING ORDER
# ─────────────────────────────────────────────────────────────────────────────
def approach_F():
    print("\n" + "="*70, flush=True)
    print("APPROACH F: GRILLE AS SUBSTITUTION ALPHABET → READING ORDER", flush=True)
    print("="*70, flush=True)
    results = []

    # F1: First occurrence ordering
    # The extract defines a priority ordering for each letter:
    # first letter seen → priority 0, second unique letter → priority 1, etc.
    seen_order = {}
    for i, c in enumerate(GRILLE_EXTRACT):
        if c not in seen_order:
            seen_order[c] = len(seen_order)
    print(f"  First-occurrence order: {seen_order}", flush=True)

    # For each K4 char, its priority is seen_order[char]
    # Sort K4 positions by (priority, position) → reading order
    k4_priorities = [(seen_order.get(K4[i], 25), i) for i in range(97)]
    perm_F1 = [p[1] for p in sorted(k4_priorities)]
    r = test_perm(perm_F1, "F_first_occurrence")
    results.append(r)

    # Inverse
    inv_F1 = [0]*97
    for idx, p in enumerate(perm_F1):
        inv_F1[p] = idx
    r = test_perm(inv_F1, "F_inv_first_occurrence")
    results.append(r)

    # F2: Extract defines a substitution cipher directly
    # Build substitution alphabet from extract (first 26 unique letters in order)
    subst_alpha = ''
    for c in GRILLE_EXTRACT:
        if c not in subst_alpha and len(subst_alpha) < 26:
            subst_alpha += c
    # Fill missing letters
    for c in AZ:
        if c not in subst_alpha:
            subst_alpha += c
    print(f"  Extract substitution alphabet: {subst_alpha}", flush=True)
    assert len(subst_alpha) == 26

    subst_ai = {c: i for i, c in enumerate(subst_alpha)}
    # Decrypt K4 using this as alphabet (it's a complete alphabet now)
    for kw in KEYWORDS:
        pt = vig_dec(K4, kw, subst_alpha, subst_ai)
        ene = pt.find(CRIB_ENE)
        bc  = pt.find(CRIB_BC)
        if ene >= 0 or bc >= 0:
            sc = qscore(pt)
            print(f"  *** F2 CRIB HIT: key={kw} ENE@{ene} BC@{bc} score={sc:.3f}", flush=True)
            print(f"      PT: {pt}", flush=True)
            d = {'label': f'F2_subst_{kw}', 'key': kw, 'cipher': 'vig_GRILLE', 'ene': ene, 'bc': bc, 'pt': pt}
            HITS.append(d); save_result(d)

    # F3: Extract letter order as reading order
    # Each letter in extract corresponds to a K4 position in some mapping
    # The n-th occurrence of letter X maps to the n-th position of X in K4
    # Build mapping: for each letter, list its positions in extract and in K4
    extract_positions = defaultdict(list)  # letter → [positions in extract]
    k4_positions = defaultdict(list)       # letter → [positions in K4]
    for i, c in enumerate(GRILLE_EXTRACT):
        extract_positions[c].append(i)
    for i, c in enumerate(K4):
        k4_positions[c].append(i)

    # Build permutation: extract[i] maps to k4 position
    # For each extract position, find corresponding K4 position
    perm_F3 = [-1] * 97
    extract_count = defaultdict(int)
    assigned_k4 = set()
    valid = True
    for i in range(min(106, 97)):
        c = GRILLE_EXTRACT[i]
        count = extract_count[c]
        k4_pos_list = k4_positions[c]
        if count < len(k4_pos_list):
            k4_pos = k4_pos_list[count]
            perm_F3[i] = k4_pos
            assigned_k4.add(k4_pos)
        extract_count[c] += 1

    # Check validity and fill gaps
    unassigned_extract = [i for i in range(97) if perm_F3[i] == -1]
    unassigned_k4 = [p for p in range(97) if p not in assigned_k4]
    for ex_pos, k4_pos in zip(unassigned_extract, unassigned_k4):
        perm_F3[ex_pos] = k4_pos
    if validate_perm(perm_F3):
        r = test_perm(perm_F3, "F_extract_to_k4_match")
        results.append(r)

    # F4: Use extract as Vigenère key directly (running key from extract[0:97])
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        for style in ['vig', 'beau']:
            if style == 'vig':
                pt = vig_dec(K4, GRILLE_EXTRACT[:97], alpha, ai)
            else:
                pt = beau_dec(K4, GRILLE_EXTRACT[:97], alpha, ai)
            ene = pt.find(CRIB_ENE)
            bc  = pt.find(CRIB_BC)
            if ene >= 0 or bc >= 0:
                sc = qscore(pt)
                print(f"  *** F4 DIRECT KEY HIT: {style}/{alpha_name} ENE@{ene} BC@{bc}", flush=True)
                print(f"      PT: {pt}", flush=True)
                d = {'label': f'F4_{style}_{alpha_name}', 'ene': ene, 'bc': bc, 'pt': pt}
                HITS.append(d); save_result(d)

    # F5: Grille extract as key starting at different offsets
    for offset in range(1, 10):
        key_text = GRILLE_EXTRACT[offset:offset+97]
        if len(key_text) < 97:
            key_text = key_text + GRILLE_EXTRACT[:97-len(key_text)]
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            pt = vig_dec(K4, key_text, alpha, ai)
            ene = pt.find(CRIB_ENE)
            bc  = pt.find(CRIB_BC)
            if ene >= 0 or bc >= 0:
                sc = qscore(pt)
                print(f"  *** F5 OFFSET KEY: off={offset} {alpha_name} ENE@{ene} BC@{bc}", flush=True)
                print(f"      PT: {pt}", flush=True)
                d = {'label': f'F5_off{offset}_{alpha_name}', 'ene': ene, 'bc': bc, 'pt': pt}
                HITS.append(d); save_result(d)

    report_best(results, "F")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH G: GRILLE HOLE COORDINATE ORDERINGS
# ─────────────────────────────────────────────────────────────────────────────
def approach_G():
    print("\n" + "="*70, flush=True)
    print("APPROACH G: GRILLE HOLE COORDINATE ORDERINGS", flush=True)
    print("="*70, flush=True)
    results = []

    # We have 107 holes, 106 have letters (1 is blank/off-grid)
    # Select 97 from 107 holes for reading order of K4
    print(f"  Holes: {HOLES[:10]}... (total {len(HOLES)})", flush=True)

    hole_rows = [h[0] for h in HOLES]
    hole_cols = [h[1] for h in HOLES]

    # G1: Sort holes by different criteria → use first 97 → reading order for K4
    sort_schemes = [
        ("row_col",     lambda h: (h[0], h[1])),         # default (already done in e_unscramble)
        ("col_row",     lambda h: (h[1], h[0])),          # column-major
        ("col_rev_row", lambda h: (h[1], -h[0])),         # column then reversed row
        ("row_rev_col", lambda h: (h[0], -h[1])),         # row then reversed col
        ("diag_sum",    lambda h: (h[0]+h[1], h[0])),     # diagonal sum
        ("diag_diff",   lambda h: (h[0]-h[1], h[0])),     # anti-diagonal
        ("col_density", lambda h: (hole_cols.count(h[1]), h[1], h[0])),  # by column density
        ("row_density", lambda h: (hole_rows.count(h[0]), h[0], h[1])),  # by row density
        ("manhattan",   lambda h: (h[0]+h[1], h[0]-h[1])), # Manhattan from origin
        ("reverse",     lambda h: (-h[0], -h[1])),         # reverse row-col order
    ]

    for scheme_name, key_fn in sort_schemes:
        sorted_holes = sorted(HOLES, key=key_fn)
        # Use first 97 holes as reading order
        # Each hole n tells us which K4 position to read for real_CT[n]
        # BUT: we need to map holes → K4 positions somehow
        # The simplest: hole n → K4[n] (trivially identity for n<97)
        # Alternative: hole's column position (mod 97) → K4 position
        #              or flat index of hole in grid

        # G1a: Use hole INDEX (in new sorted order) directly
        # reading_order[i] = sorted_holes[i] → K4 position in row-major order
        flat_indices = [h[0]*33 + h[1] for h in sorted_holes[:97]]
        flat_97 = [f % 97 for f in flat_indices]
        # This may not be a valid permutation, so we need to handle collisions
        perm_G1a = argsort(flat_97)
        if validate_perm(perm_G1a):
            r = test_perm(perm_G1a, f"G_{scheme_name}_flat_argsort")
            results.append(r)

        # G1b: Use sorted hole positions' column indices as permutation key
        col_seq = [h[1] for h in sorted_holes[:97]]
        if len(set(col_seq)) == len(col_seq):  # all unique columns
            perm_G1b = argsort(col_seq)
            if validate_perm(perm_G1b):
                r = test_perm(perm_G1b, f"G_{scheme_name}_col_seq")
                results.append(r)

    # G2: Row indices of holes as columnar key
    row_seq = hole_rows[:97]
    perm_G2 = argsort(row_seq)
    r = test_perm(perm_G2, "G_row_seq_argsort")
    results.append(r)

    col_seq = hole_cols[:97]
    perm_G3 = argsort(col_seq)
    r = test_perm(perm_G3, "G_col_seq_argsort")
    results.append(r)

    # G4: Use holes' row×col products mod 97
    products = [(h[0] * h[1]) % 97 for h in HOLES[:97]]
    # Build a permutation from these (may have collisions)
    perm_G4 = argsort(products)
    r = test_perm(perm_G4, "G_row_times_col_mod97")
    results.append(r)

    # G5: Knights-tour-like ordering: sort by (col+row*2) and similar
    for mult in range(1, 8):
        seq = [(h[1] + h[0]*mult) % 97 for h in HOLES[:97]]
        perm = argsort(seq)
        if validate_perm(perm):
            r = test_perm(perm, f"G_knight_mult{mult}")
            results.append(r)

    # G6: Every-other-hole selections (skip holes 0,2,4,... or 1,3,5,...)
    for start in [0, 1]:
        selected = HOLES[start::2][:97]
        if len(selected) == 97:
            flat = [(h[0]*33 + h[1]) % 97 for h in selected]
            perm = argsort(flat)
            if validate_perm(perm):
                r = test_perm(perm, f"G_every_other_start{start}")
                results.append(r)

    # G7: Skip the one "blank" hole (108th or 107th)
    # We have 107 holes total, 106 have letters. Drop the blank one.
    # Which hole is blank? Need to figure out. Let's skip the first and last.
    for skip_idx in [0, 106, 53]:
        valid_holes = [h for i, h in enumerate(HOLES) if i != skip_idx]
        if len(valid_holes) >= 97:
            selected = valid_holes[:97]
            flat = [(h[0]*33 + h[1]) % 97 for h in selected]
            perm = argsort(flat)
            if validate_perm(perm):
                r = test_perm(perm, f"G_skip_hole{skip_idx}")
                results.append(r)

    report_best(results, "G")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH H: CLOCK CIPHER (WELTZEITUHR)
# ─────────────────────────────────────────────────────────────────────────────
def approach_H():
    print("\n" + "="*70, flush=True)
    print("APPROACH H: CLOCK CIPHER (WELTZEITUHR)", flush=True)
    print("="*70, flush=True)
    results = []

    # K4 has 97 chars. Berlin Clock has 24 segments (4+4+11+4+1 second indicator)
    # 97 = 4×24 + 1
    # The 11-segment row matches BERLINCLOCK (11 chars, positions 63-73)

    # H1: Group K4 into chunks of 24, try different group rotations/reorderings
    groups_of_24 = [K4[i*24:(i+1)*24] for i in range(4)]  # 4 groups of 24
    remainder = K4[96:]  # 1 char
    print(f"  Groups: {[len(g) for g in groups_of_24]}, remainder: {remainder}", flush=True)

    # H1a: All permutations of the 4 groups
    for group_order in iperm(range(4)):
        candidate_ct = ''.join(groups_of_24[i] for i in group_order) + remainder
        r = test_ct(candidate_ct[:97], f"H_group24_{''.join(map(str,group_order))}")
        results.append(r)

    # H1b: Rotate within each group and try all combinations
    for rot0 in range(0, 24, 6):
        for rot1 in range(0, 24, 6):
            g0 = groups_of_24[0][rot0:] + groups_of_24[0][:rot0]
            g1 = groups_of_24[1][rot1:] + groups_of_24[1][:rot1]
            candidate_ct = g0 + g1 + groups_of_24[2] + groups_of_24[3] + remainder
            r = test_ct(candidate_ct[:97], f"H_rot_g0{rot0}_g1{rot1}")
            results.append(r)

    # H2: Clock-based positional permutation
    # 4 rows: 5h (4 segments), 1h (4 segments), 5m (11 segments), 1m (4 segments)
    # Reading order: 5h block 1-4, 1h block 1-4, 5m block 1-11, 1m block 1-4
    # Possible mapping: K4 positions → clock segments (4+4+11+4 = 23 per 24-cycle)
    clock_row_sizes = [4, 4, 11, 4]
    clock_cycle = sum(clock_row_sizes)  # 23
    for cycle_len in [23, 24]:
        perm_H2 = []
        # Build reading order: positions within clock period
        for i in range(97):
            cycle_num = i // cycle_len
            pos_in_cycle = i % cycle_len
            # Map clock position to K4 position
            # clock rows: 0..3, 4..7, 8..18, 19..22
            perm_H2.append(i)  # identity as baseline - we'll modify
        # Actually: reorder based on clock row structure
        # Row 1 (5h): positions 0, 4, 8, 12, ... (every 24)
        # Row 2 (1h): positions 1, 5, 9, 13, ...
        # etc.
        pass  # Will implement below

    # H3: Interleave by Berlin Clock row structure
    # If K4 was laid out as clock display:
    # Row 1 (4 segments × 5h): every 24th char starting 0, 1, 2, 3
    # Row 2 (4 segments × 1h): every 24th char starting 4, 5, 6, 7
    # Row 3 (11 segments × 5m): every 24th char starting 8..18
    # Row 4 (4 segments × 1m): every 24th char starting 19..22
    for base_period in [24, 23, 22]:
        segments = []
        for seg in range(base_period):
            seg_chars = K4[seg::base_period]
            segments.append(seg_chars)

        # Try different row structures
        for row_structure in [[4,4,11,4], [4,4,11,5], [4,4,12,4]]:
            if sum(row_structure) != base_period:
                continue
            reordered = []
            pos = 0
            for row_size in row_structure:
                row_segs = segments[pos:pos+row_size]
                for seg in row_segs:
                    reordered.extend(list(seg))
                pos += row_size
            candidate_ct = ''.join(reordered[:97])
            if len(candidate_ct) == 97:
                label = f"H_clock_p{base_period}_{'_'.join(map(str,row_structure))}"
                r = test_ct(candidate_ct, label)
                results.append(r)

    # H4: Weltzeituhr time encoding: 24 zones on clock face
    # Each hour zone = 360/24 = 15 degrees
    # The BERLINCLOCK crib positions (63-73) have 11 chars = 11 segments
    # Try circular permutations of K4 in groups of 24
    for start in range(24):
        # Rotate K4 by start×(97/24) positions
        rot = (start * 97) // 24
        candidate_ct = K4[rot:] + K4[:rot]
        r = test_ct(candidate_ct, f"H_circular_rot{rot}")
        results.append(r)

    report_best(results, "H")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH I: MORSE CODE AND POSITIONAL ENCODING VIA T-ABSENCE
# ─────────────────────────────────────────────────────────────────────────────
def approach_I():
    print("\n" + "="*70, flush=True)
    print("APPROACH I: MORSE/POSITIONAL ENCODING VIA T-ABSENCE", flush=True)
    print("="*70, flush=True)
    results = []

    # T positions in K4
    t_positions = [i for i, c in enumerate(K4) if c == 'T']
    non_t_positions = [i for i, c in enumerate(K4) if c != 'T']
    print(f"  T at positions: {t_positions}", flush=True)
    print(f"  Non-T count: {len(non_t_positions)}", flush=True)

    # I1: T positions as markers — reorder K4 with T-marked chars last/first
    # Place non-T chars first, then T chars
    perm_I1 = non_t_positions + t_positions
    if validate_perm(perm_I1):
        r = test_perm(perm_I1, "I_nonT_first")
        results.append(r)

    # T chars first, then non-T
    perm_I2 = t_positions + non_t_positions
    if validate_perm(perm_I2):
        r = test_perm(perm_I2, "I_T_first")
        results.append(r)

    # I2: K0 Morse code walkway timing
    # K0 text (Morse on walkway): SHADOWS FORCES / VIRTUAL FORCES etc.
    # Morse values (dots/dashes count per letter):
    MORSE_LENGTHS = {
        'A':2,'B':4,'C':4,'D':3,'E':1,'F':4,'G':3,'H':4,'I':2,'J':4,
        'K':3,'L':4,'M':2,'N':2,'O':3,'P':4,'Q':4,'R':3,'S':3,'T':1,
        'U':3,'V':4,'W':3,'X':4,'Y':4,'Z':4
    }
    # K0 walkway text (various sources suggest these)
    k0_candidates = [
        "SHADOWFORCES",
        "VIRTUALLYINVISIBLESHADOWFORCES",
        "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION",
    ]

    for k0_text in k0_candidates:
        # Generate Morse length sequence
        morse_seq = [MORSE_LENGTHS.get(c, 2) for c in k0_text if c in AZ]
        if len(morse_seq) < 97:
            morse_seq = (morse_seq * 4)[:97]
        else:
            morse_seq = morse_seq[:97]
        assert len(morse_seq) == 97

        perm_morse = argsort(morse_seq)
        r = test_perm(perm_morse, f"I_morse_{''.join(k0_text[:8])}")
        results.append(r)

    # I3: Letter frequency of K4 as permutation weight
    # High-frequency chars → early in permutation
    freq = Counter(K4)
    # Sort positions by (frequency of char at position, AZ index of char, position)
    weighted = [(freq[K4[i]], AZI[K4[i]], i) for i in range(97)]
    perm_I3 = [x[2] for x in sorted(range(97), key=lambda i: weighted[i])]
    r = test_perm(perm_I3, "I_freq_weighted")
    results.append(r)

    # Reverse (most frequent first)
    perm_I3r = [x[2] for x in sorted(range(97), key=lambda i: (-weighted[i][0], weighted[i][1], weighted[i][2]))]
    r = test_perm(perm_I3r, "I_freq_weighted_rev")
    results.append(r)

    # I4: Missing letters encode positional data
    # Letters in AZ not in K4... actually all 26 are present
    # Letters in AZ not in grille extract: only T
    # T marks special positions; use non-T chars of K4 to build permutation
    # Map K4 non-T chars to positions 0..90 (there are 91 non-T chars in K4)
    t_count = K4.count('T')  # should be 6
    print(f"  K4 T count: {t_count}", flush=True)

    # I5: Treat K4 as binary (T=1, not-T=0) and use as permutation seed
    binary_T = [1 if c == 'T' else 0 for c in K4]
    # Build permutation: zeros first (all non-T positions by their K4 order)
    # then ones (T positions)
    # Already done in I1/I2, but try different scales

    # I6: T positions as "null" positions — read remaining 91 chars
    # "8 Lines 73" — 8 rows of approximately 73/8 ≈ 9 chars + extra
    # If 6 T positions are nulls, remaining 91 chars in 8 lines of ~11 or 7 lines...
    for lines in range(4, 16):
        non_t_chars = ''.join(K4[i] for i in non_t_positions)
        n_nt = len(non_t_chars)
        if n_nt % lines == 0:
            width = n_nt // lines
        else:
            width = n_nt // lines + 1
        # Lay out non-T chars in grid, read column-major
        nrows = math.ceil(n_nt / width)
        padded = non_t_chars + 'X' * (nrows * width - n_nt)
        # Columnar transposition
        for col_order_key in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
            if len(col_order_key) >= width:
                key_part = col_order_key[:width]
            else:
                key_part = (col_order_key * 4)[:width]
            col_order = argsort(key_part)
            candidate = ''.join(padded[r*width + c] for c in col_order for r in range(nrows))
            candidate = candidate.replace('X', '')[:min(97, n_nt)]
            if len(candidate) >= 11:
                for kw in KEYWORDS:
                    for cname, cfn in CIPHERS:
                        pt = cfn(candidate, kw)
                        if CRIB_ENE in pt or CRIB_BC in pt:
                            sc = qscore(pt)
                            print(f"  *** I6 HIT: lines={lines} key={col_order_key} kw={kw} {cname}", flush=True)
                            print(f"      PT: {pt}", flush=True)
                            d = {'label': f'I6_lines{lines}_{col_order_key}_{kw}_{cname}', 'pt': pt, 'score': sc}
                            HITS.append(d); save_result(d)

    report_best(results, "I")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH J: IDBYROWS — GRID READING WITH KEYWORD COLUMN ORDERING
# ─────────────────────────────────────────────────────────────────────────────
def approach_J():
    print("\n" + "="*70, flush=True)
    print("APPROACH J: IDBYROWS — KEYWORD COLUMN ORDERING", flush=True)
    print("="*70, flush=True)
    results = []

    # "ID BY ROWS" — lay K4 in grid, identify by rows in keyword order
    # This is different from standard columnar transposition:
    # In standard columnar: write by rows, read by columns in key order
    # In "ID by rows": the rows themselves are identified/reordered by key

    for width in range(7, 24):
        nrows = math.ceil(97 / width)
        # Pad K4 to exact grid size
        padded = K4 + 'X' * (nrows * width - 97)
        grid_rows = [padded[r*width:(r+1)*width] for r in range(nrows)]

        # J1: Standard columnar transposition (read by columns in key order)
        for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST', 'SHADOW', 'BERLINCLOCK', 'EASTNORTHEAST']:
            if len(kw) >= width:
                key_part = kw[:width]
            else:
                key_part = (kw * 4)[:width]
            col_order = argsort(key_part)
            # Read chars column by column in key order
            candidate_ct = ''.join(grid_rows[r][c] for c in col_order for r in range(nrows) if r*width + c < 97)
            candidate_ct = candidate_ct.replace('X', '')[:97]
            if len(candidate_ct) == 97:
                r = test_ct(candidate_ct, f"J_col_w{width}_{kw[:8]}")
                results.append(r)

        # J2: Read by ROWS in keyword order (reorder rows by key)
        if nrows <= 15:
            for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
                if len(kw) >= nrows:
                    key_part = kw[:nrows]
                else:
                    key_part = (kw * 4)[:nrows]
                row_order = argsort(key_part)
                candidate_ct = ''.join(grid_rows[r][:width] for r in row_order)
                candidate_ct = ''.join(c for c in candidate_ct if c != 'X')[:97]
                if len(candidate_ct) == 97:
                    r = test_ct(candidate_ct, f"J_row_w{width}_{kw[:8]}")
                    results.append(r)

        # J3: Write by columns, read by rows (transpose then keyword-sort rows)
        # This is the "ID by rows" interpretation
        for kw in ['KRYPTOS', 'ABSCISSA']:
            if len(kw) >= width:
                key_part = kw[:width]
            else:
                key_part = (kw * 4)[:width]
            col_order = argsort(key_part)

            # Reverse: build candidate by writing columns in natural order
            col_texts = []
            for c in range(width):
                col_text = ''.join(grid_rows[r][c] for r in range(nrows) if r*width + c < 97)
                col_texts.append(col_text)
            # Read column-order using key
            candidate_ct = ''.join(col_texts[c] for c in col_order)[:97]
            if len(candidate_ct) == 97:
                r = test_ct(candidate_ct, f"J_idbyrows_w{width}_{kw[:8]}")
                results.append(r)

    report_best(results, "J")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH K: DOUBLED-LETTER POSITION ENCODING
# ─────────────────────────────────────────────────────────────────────────────
def approach_K():
    print("\n" + "="*70, flush=True)
    print("APPROACH K: DOUBLED-LETTER POSITION ENCODING", flush=True)
    print("="*70, flush=True)
    results = []

    # Find doubled (consecutive) letters in K4
    doubles = []
    for i in range(96):
        if K4[i] == K4[i+1]:
            doubles.append((i, K4[i]))
    print(f"  Doubles in K4: {doubles}", flush=True)
    # K4: BB(18), QQ(25-26), SS(31-32), ZZ(46-47), TT(67-68)
    # 5 pairs → 10 positions involved

    double_positions = []
    for i, _ in doubles:
        double_positions.extend([i, i+1])
    single_positions = [i for i in range(97) if i not in double_positions]
    print(f"  Double positions: {double_positions}", flush=True)
    print(f"  Single positions: {len(single_positions)} positions", flush=True)

    # K1: Read singles first, then doubles
    perm_K1 = single_positions + double_positions
    if validate_perm(perm_K1):
        r = test_perm(perm_K1, "K_singles_first")
        results.append(r)

    # K2: Read doubles first, then singles
    perm_K2 = double_positions + single_positions
    if validate_perm(perm_K2):
        r = test_perm(perm_K2, "K_doubles_first")
        results.append(r)

    # K3: Interleave doubles and singles
    interleaved = []
    max_len = max(len(double_positions), len(single_positions))
    for i in range(max_len):
        if i < len(single_positions):
            interleaved.append(single_positions[i])
        if i < len(double_positions):
            interleaved.append(double_positions[i])
    perm_K3 = interleaved[:97]
    if len(perm_K3) == 97 and validate_perm(perm_K3):
        r = test_perm(perm_K3, "K_interleave_singles_doubles")
        results.append(r)

    # K4: Use double-letter positions as structural markers
    # For 5 doubles, 97/5 ≈ 19.4 → double pairs every ~20 chars
    # This suggests a period-20 or period-19 structure
    double_gaps = [doubles[i+1][0] - doubles[i][0] for i in range(len(doubles)-1)]
    print(f"  Gap between doubles: {double_gaps}", flush=True)

    # K5: Use QQ, SS, ZZ positions (3 of the 5 doubles are the most striking)
    qq_pos = [i for i, c in enumerate(K4) if c == 'Q' and i < 96 and K4[i+1] == 'Q']
    ss_pos = [i for i, c in enumerate(K4) if c == 'S' and i < 96 and K4[i+1] == 'S']
    zz_pos = [i for i, c in enumerate(K4) if c == 'Z' and i < 96 and K4[i+1] == 'Z']
    print(f"  QQ at: {qq_pos}, SS at: {ss_pos}, ZZ at: {zz_pos}", flush=True)

    # The QQ at positions 25,26 and QQ-related: QQPRNG between E-N-E and B-C cribs?
    # These doubles might be "separator" signals

    # K6: Block between doubles as segments
    # Segments: [0:18], [18:20], [20:25], [25:27], [27:31], [31:33], [33:46], [46:48], [48:67], [67:69], [69:97]
    # Read segments in different orders
    segment_boundaries = [0] + [i for i, _ in doubles] + [i+2 for i, _ in doubles] + [97]
    segment_boundaries = sorted(set(segment_boundaries))
    segments = []
    for i in range(len(segment_boundaries)-1):
        s = segment_boundaries[i]
        e = segment_boundaries[i+1]
        segments.append(list(range(s, e)))
    print(f"  Segments: {[(s[0], len(s)) for s in segments]}", flush=True)

    # Try all permutations of segments (if feasible)
    if len(segments) <= 8:
        for seg_order in iperm(range(len(segments))):
            perm_K6 = []
            for si in seg_order:
                perm_K6.extend(segments[si])
            if len(perm_K6) == 97 and validate_perm(perm_K6):
                r = test_perm(perm_K6, f"K_seg_order_{''.join(map(str,seg_order))}")
                results.append(r)
    else:
        # Just try reversed segments and reversed order
        for seg_order in [list(range(len(segments)-1, -1, -1)),
                          list(range(len(segments)//2, len(segments))) + list(range(len(segments)//2))]:
            perm_K6 = []
            for si in seg_order:
                perm_K6.extend(segments[si])
            if len(perm_K6) == 97 and validate_perm(perm_K6):
                label = f"K_seg_custom_{''.join(map(str,seg_order[:5]))}"
                r = test_perm(perm_K6, label)
                results.append(r)

    report_best(results, "K")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH L: KA-INDEX MAPPING → PERMUTATION
# ─────────────────────────────────────────────────────────────────────────────
def approach_L():
    print("\n" + "="*70, flush=True)
    print("APPROACH L: KA-INDEX AND ALPHABET MAPPING PERMUTATIONS", flush=True)
    print("="*70, flush=True)
    results = []

    # L1: K4 chars → KA positions → scale to 0-96 range
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        n = len(alpha)
        # Map each K4[i] to its position in alpha, scale to 0..96
        raw = [ai.get(K4[i], 0) * 97 // n for i in range(97)]
        perm_L1 = argsort(raw)
        r = test_perm(perm_L1, f"L_alpha_scaled_{alpha_name}")
        results.append(r)

    # L2: Positional cipher — AZ.index(K4[i]) directly as an index mod 97
    # Creates a function on K4 positions
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        n = len(alpha)
        # Build a permutation by following chains:
        # chain[i] → ai[K4[i]] → ai[K4[ai[K4[i]]]] → ...
        # This creates a permutation via the function f(i) = ai[K4[i]] % 97
        f = [ai.get(K4[i], 0) % 97 for i in range(97)]  # but values 0-25, not 0-96
        # Adjust to get 97-range: f(i) = ai[K4[i]] * 4 % 97
        for scale in [4, 5, 3]:
            f_scaled = [(ai.get(K4[i], 0) * scale + i // 4) % 97 for i in range(97)]
            perm = argsort(f_scaled)
            if validate_perm(perm):
                r = test_perm(perm, f"L_chain_{alpha_name}_scale{scale}")
                results.append(r)

    # L3: AZ position of each K4 char used as a "pointer"
    # Build a mapping: position i → AZ.index(K4[i])
    # Since AZ indices are 0-25 and we need 0-96, chain through
    # Start at position 0: value = AZI[K4[0]] = 14 ('O')
    # Next step: go to position 14, value = AZI[K4[14]] = ...
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        visited = [False] * 97
        order = []
        pos = 0
        for _ in range(97):
            if visited[pos]:
                # Find first unvisited
                found = False
                for p in range(97):
                    if not visited[p]:
                        pos = p
                        found = True
                        break
                if not found:
                    break
            order.append(pos)
            visited[pos] = True
            # Jump: next position is (current_letter_index * some_prime) % 97
            for prime in [4, 7, 11, 13]:
                next_pos = (ai.get(K4[pos], 0) * prime) % 97
                if not visited[next_pos]:
                    pos = next_pos
                    break
                else:
                    pos = next_pos  # Will be caught by visited check
        if len(order) == 97 and validate_perm(order):
            r = test_perm(order, f"L_jump_{alpha_name}")
            results.append(r)

    # L4: Use AZ→KA substitution as a permutation of K4
    # Apply the AZ→KA mapping to K4's char values
    AZ_to_KA_idx = {c: KAI[c] for c in AZ}
    ka_vals = [AZ_to_KA_idx[c] for c in K4]  # values 0-25
    # Scale to 0-96 range
    scaled_ka = [v * 97 // 26 for v in ka_vals]
    perm_L4 = argsort(scaled_ka)
    r = test_perm(perm_L4, "L_AZ_to_KA_scaled")
    results.append(r)

    report_best(results, "L")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH M: KNOWN-KEYWORD REVERSE ENGINEERING
# ─────────────────────────────────────────────────────────────────────────────
def approach_M():
    print("\n" + "="*70, flush=True)
    print("APPROACH M: KNOWN-KEYWORD REVERSE ENGINEERING", flush=True)
    print("="*70, flush=True)
    results = []

    # M1: Assume KRYPTOS is the key and Vigenère is the cipher
    # Then real_CT must = Vigenère_encrypt(English_PT, KRYPTOS)
    # For positions where PT is known from cribs (positions 0-22 relative to cribs):
    # The cribs tell us what PT should be at specific positions IF we knew the permutation
    # But under scrambling, cribs can be ANYWHERE in PT
    # So this approach: assume cribs start at position 0 of the PT

    # For each keyword and cipher, compute what real_CT would look like
    # if PT starts with EASTNORTHEAST
    for kw in KEYWORDS:
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            n = len(alpha)
            ki = [ai.get(c, 0) for c in kw]

            # Vigenère: CT[i] = alpha[(PT[i] + key[i%len]) % n]
            # PT starts EASTNORTHEAST → first 13 chars of real_CT
            pt_crib = CRIB_ENE + 'X' * (97 - len(CRIB_ENE))
            real_ct_crib = ''.join(
                alpha[(ai.get(pt_crib[i], 0) + ki[i % len(ki)]) % n]
                for i in range(97)
            )
            # Now: real_ct_crib is what we expect K4 (permuted) to look like
            # Check: does K4 contain all chars of real_ct_crib? (multiset match)
            if Counter(real_ct_crib) == Counter(K4):
                print(f"  *** M1: K4 is anagram of expected CT! kw={kw} {alpha_name} vig", flush=True)
                # Find the permutation: for each position in real_ct_crib,
                # find which K4 position has that character
                # (Will need to handle duplicates carefully)
                d = {'label': f'M1_match_{kw}_{alpha_name}', 'real_ct': real_ct_crib, 'kw': kw}
                HITS.append(d); save_result(d)

            # Beaufort: CT[i] = alpha[(key[i%len] - PT[i]) % n]
            real_ct_beau = ''.join(
                alpha[(ki[i % len(ki)] - ai.get(pt_crib[i], 0)) % n]
                for i in range(97)
            )
            if Counter(real_ct_beau) == Counter(K4):
                print(f"  *** M1: K4 is anagram of expected CT! kw={kw} {alpha_name} beau", flush=True)
                d = {'label': f'M1_beau_match_{kw}_{alpha_name}', 'real_ct': real_ct_beau, 'kw': kw}
                HITS.append(d); save_result(d)

    # M2: Constraint-based permutation
    # We know: at PT positions where crib falls, CT chars must encode those PT chars
    # If cribs are at positions 0-12 (ENE) and 50-60 (BC) of PT:
    # Then the permuted K4 must have specific chars at those positions
    # The CARVED K4 chars at positions that map to PT positions 0-12 must encode EASTNORTHEAST

    # M3: Systematic search for where cribs land in PT
    # For short keywords, try ALL possible starting positions for each crib
    for kw in ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']:
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            n = len(alpha)
            ki = [ai.get(c, 0) for c in kw]

            # For ENE crib at PT position ene_start:
            # real_CT[ene_start + j] = vig_enc(ENE[j], key[ene_start+j])
            # = alpha[(ai[ENE[j]] + ki[(ene_start+j) % len(ki)]) % n]
            for ene_start in range(85):
                # What real_CT chars are needed at positions ene_start..ene_start+12?
                needed_ene = ''.join(
                    alpha[(ai.get(CRIB_ENE[j], 0) + ki[(ene_start+j) % len(ki)]) % n]
                    for j in range(13)
                )
                # Check: does K4 contain all these chars (as a subsequence of the multiset)?
                # Quick check: are all chars in needed_ene present in K4?
                needed_cnt = Counter(needed_ene)
                k4_cnt = Counter(K4)
                if all(k4_cnt.get(c, 0) >= needed_cnt[c] for c in needed_cnt):
                    for bc_start in range(85):
                        if abs(bc_start - ene_start) < 11:
                            continue  # overlap
                        needed_bc = ''.join(
                            alpha[(ai.get(CRIB_BC[j], 0) + ki[(bc_start+j) % len(ki)]) % n]
                            for j in range(11)
                        )
                        needed_cnt2 = Counter(needed_ene + needed_bc)
                        if all(k4_cnt.get(c, 0) >= needed_cnt2[c] for c in needed_cnt2):
                            # Promising combination!
                            # Can we build a permutation?
                            print(f"  M3: Potential match kw={kw} {alpha_name} "
                                  f"ENE@{ene_start} BC@{bc_start}", flush=True)
                            print(f"      needed_ENE: {needed_ene}", flush=True)
                            print(f"      needed_BC:  {needed_bc}", flush=True)
                            d = {'label': f'M3_{kw}_{alpha_name}_e{ene_start}_b{bc_start}',
                                 'kw': kw, 'alpha': alpha_name, 'ene_start': ene_start,
                                 'bc_start': bc_start, 'needed_ene': needed_ene, 'needed_bc': needed_bc}
                            save_result(d)

    report_best(results, "M")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH N: NOVEL STRUCTURAL PERMUTATIONS
# ─────────────────────────────────────────────────────────────────────────────
def approach_N():
    print("\n" + "="*70, flush=True)
    print("APPROACH N: NOVEL STRUCTURAL PERMUTATIONS", flush=True)
    print("="*70, flush=True)
    results = []

    # N1: Palindromic/mirror permutations
    # N chars: p[i] and p[N-1-i] are "mirrors"
    # Build by interleaving first half and reversed second half
    half = 97 // 2   # 48
    for offset in range(-5, 6):
        mid = 48 + offset
        if mid < 1 or mid > 96:
            continue
        front = list(range(mid))
        back  = list(range(96, mid-1, -1))
        # Take alternating from front and back
        perm = []
        for i in range(max(len(front), len(back))):
            if i < len(front):
                perm.append(front[i])
            if i < len(back) and len(perm) < 97:
                perm.append(back[i])
        perm = perm[:97]
        if len(perm) == 97 and validate_perm(perm):
            r = test_perm(perm, f"N_palindrome_mid{mid}")
            results.append(r)

    # N2: Prime-based permutation (skip by prime steps)
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    for p in primes:
        if math.gcd(p, 97) == 1:  # 97 is prime, so all p<97 work
            perm_N2 = [(p * i) % 97 for i in range(97)]
            if validate_perm(perm_N2):
                r = test_perm(perm_N2, f"N_prime_step{p}")
                results.append(r)
                # Inverse
                inv = argsort(perm_N2)
                r = test_perm(inv, f"N_prime_step{p}_inv")
                results.append(r)

    # N3: Strided permutations (all step sizes coprime to 97)
    # Since 97 is prime, ALL steps 1-96 are coprime
    for step in range(2, 97):
        perm_N3 = [(step * i) % 97 for i in range(97)]
        if validate_perm(perm_N3):
            r = test_perm(perm_N3, f"N_stride{step}")
            results.append(r)
            if r and (r.get('ene', -1) >= 0 or r.get('bc', -1) >= 0):
                print(f"  *** N3 CRIB HIT: stride={step}", flush=True)
                break  # continue for all steps regardless

    # N4: Bit-reversal permutation (standard FFT bit-reversal)
    # For N not a power of 2, use a generalized version
    # log2(97) ≈ 6.6, so use 7-bit reversal mod 97
    def bit_rev_7(i):
        # Reverse 7 bits
        result = 0
        for _ in range(7):
            result = (result << 1) | (i & 1)
            i >>= 1
        return result

    perm_N4 = [bit_rev_7(i) % 97 for i in range(97)]
    perm_N4 = argsort(perm_N4)
    if validate_perm(perm_N4):
        r = test_perm(perm_N4, "N_bit_reversal")
        results.append(r)

    # N5: Gray code ordering
    def gray(n):
        return n ^ (n >> 1)
    gray_seq = [gray(i) % 97 for i in range(97)]
    perm_N5 = argsort(gray_seq)
    if validate_perm(perm_N5):
        r = test_perm(perm_N5, "N_gray_code")
        results.append(r)

    # N6: Fibonacci-based permutation
    fib = [0, 1]
    while fib[-1] < 200:
        fib.append(fib[-1] + fib[-2])
    fib_97 = [f % 97 for f in fib[:97]]
    perm_N6 = argsort(fib_97)
    if validate_perm(perm_N6):
        r = test_perm(perm_N6, "N_fibonacci_mod97")
        results.append(r)

    # N7: Triangular number permutation
    tri = [(i*(i+1)//2) % 97 for i in range(97)]
    perm_N7 = argsort(tri)
    if validate_perm(perm_N7):
        r = test_perm(perm_N7, "N_triangular")
        results.append(r)

    # N8: K4's unique character pattern → permutation
    # First 26 unique chars of K4 define a substitution
    unique_order = ''
    for c in K4:
        if c not in unique_order:
            unique_order += c
    # Fill remaining AZ letters not in K4 (all are present, but order matters)
    print(f"  K4 unique order (first-occurrence): {unique_order}", flush=True)
    # Sort K4 positions by unique_order priority
    priority = {c: i for i, c in enumerate(unique_order)}
    perm_N8 = argsort([(priority.get(K4[i], 25), i) for i in range(97)])
    r = test_perm(perm_N8, "N_first_occurrence_K4")
    results.append(r)

    report_best(results, "N")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH O: GRILLE EXTRACT DIRECT PERMUTATION ATTEMPTS
# ─────────────────────────────────────────────────────────────────────────────
def approach_O():
    print("\n" + "="*70, flush=True)
    print("APPROACH O: EXTRACT → VALID 97-PERMUTATION CONSTRUCTIONS", flush=True)
    print("="*70, flush=True)
    results = []

    # The extract is 106 chars. We need 97. Various ways to get a valid perm:

    # O1: Use extract's KA indices mod 97
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        ext_vals = [ai.get(c, 0) for c in GRILLE_EXTRACT]  # 0-25

        # Scale to 0-96: multiply by ceil(97/26) and wrap
        scaled = [(v * 97 + i) % 97 for i, v in enumerate(ext_vals[:97])]
        perm = argsort(scaled)
        if validate_perm(perm):
            r = test_perm(perm, f"O_ext_scaled_mod97_{alpha_name}")
            results.append(r)

        # Direct mod 97 via position formula
        idx_vals = [(ai.get(GRILLE_EXTRACT[i], 0) * (i + 1)) % 97 for i in range(97)]
        perm2 = argsort(idx_vals)
        if validate_perm(perm2):
            r = test_perm(perm2, f"O_ext_pos_product_{alpha_name}")
            results.append(r)

    # O2: Take every nth extract char to build 97-element sequence
    for stride in range(1, 4):
        chars = [GRILLE_EXTRACT[(i * stride) % 106] for i in range(97)]
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            vals = [ai.get(c, 0) for c in chars]
            perm = argsort(vals)
            if validate_perm(perm):
                r = test_perm(perm, f"O_stride{stride}_{alpha_name}")
                results.append(r)

    # O3: Cumulative sum of extract letter values → permutation
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        vals = [ai.get(c, 0) for c in GRILLE_EXTRACT[:97]]
        cumsum = []
        s = 0
        for v in vals:
            s = (s + v) % 97
            cumsum.append(s)
        perm = argsort(cumsum)
        if validate_perm(perm):
            r = test_perm(perm, f"O_cumsum_{alpha_name}")
            results.append(r)

    # O4: Take top-97 of 107 holes by various metrics
    for skip_n in range(11):
        # Skip first skip_n holes (or last skip_n)
        for skip_end in [True, False]:
            if skip_end:
                selected_holes = HOLES[:107-skip_n]
            else:
                selected_holes = HOLES[skip_n:]
            if len(selected_holes) >= 97:
                # Use first 97 of selected holes
                sel97 = selected_holes[:97]
                # Map hole (r,c) → flat index mod 97
                flat = [(h[0] * 33 + h[1]) % 97 for h in sel97]
                perm = argsort(flat)
                if validate_perm(perm):
                    suffix = "end" if skip_end else "start"
                    r = test_perm(perm, f"O_holes_skip{skip_n}_{suffix}")
                    results.append(r)

    # O5: Hole coordinates → Letter at that position in K4 laid in 28-col grid
    # If K4 were written in a 28-col grid (rows), hole (r,c) maps to position r*28+c
    for grid_width in [28, 29, 30, 31, 32, 33, 34]:
        k4_positions_from_holes = []
        for h in HOLES:
            pos = h[0] * grid_width + h[1]
            if pos < 97:
                k4_positions_from_holes.append(pos)
        # Use these as a reading order
        if len(k4_positions_from_holes) >= 97:
            # Build permutation from the sequence (may have repeats - take unique)
            seen = set()
            perm = []
            for p in k4_positions_from_holes:
                if p not in seen:
                    perm.append(p)
                    seen.add(p)
            # Fill missing
            for p in range(97):
                if p not in seen:
                    perm.append(p)
            if len(perm) == 97 and validate_perm(perm):
                r = test_perm(perm, f"O_hole_k4_grid_w{grid_width}")
                results.append(r)
        elif len(k4_positions_from_holes) > 20:
            # Build what we can and supplement
            seen = set()
            perm = []
            for p in k4_positions_from_holes:
                if p not in seen:
                    perm.append(p)
                    seen.add(p)
            for p in range(97):
                if p not in seen:
                    perm.append(p)
            if len(perm) == 97 and validate_perm(perm):
                r = test_perm(perm, f"O_hole_k4_grid_w{grid_width}_partial")
                results.append(r)

    report_best(results, "O")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH P: COMBINED / DOUBLE-SCRAMBLE
# ─────────────────────────────────────────────────────────────────────────────
def approach_P():
    print("\n" + "="*70, flush=True)
    print("APPROACH P: COMBINED / DOUBLE-SCRAMBLE APPROACHES", flush=True)
    print("="*70, flush=True)
    results = []

    # P1: Apply two permutations in sequence
    # perm_A then perm_B = perm_B(perm_A(K4))
    # Use argsort(K4) and argsort(GRILLE_EXTRACT[:97]) as the two perms
    perm_k4  = argsort(K4)
    perm_ext = argsort(GRILLE_EXTRACT[:97])

    for name, perm in [("k4_then_ext", [perm_ext[perm_k4[i]] for i in range(97)]),
                        ("ext_then_k4", [perm_k4[perm_ext[i]] for i in range(97)])]:
        if validate_perm(perm):
            r = test_perm(perm, f"P_{name}")
            results.append(r)

    # P2: XOR two permutations
    for name, p1, p2 in [("k4_xor_ext", perm_k4, perm_ext)]:
        perm = [(p1[i] ^ p2[i]) % 97 for i in range(97)]
        perm = argsort(perm)
        if validate_perm(perm):
            r = test_perm(perm, f"P_{name}_argsort")
            results.append(r)

    # P3: Interleave two permutations
    half = 97 // 2
    interleaved = []
    for i in range(half):
        interleaved.append(perm_k4[i])
        interleaved.append(perm_ext[i])
    interleaved.append(perm_k4[48] if perm_k4[48] not in interleaved else perm_ext[48])
    if len(set(interleaved[:97])) == 97 and validate_perm(interleaved[:97]):
        r = test_perm(interleaved[:97], "P_interleave_k4_ext")
        results.append(r)

    # P4: Use the "IDBYROWS" = 97 interpretation
    # If K4 is laid out in rows of length L, and we "ID" each row by some number,
    # then reading in that number order gives the unscrambled text
    for L in range(7, 15):
        nrows = math.ceil(97 / L)
        padded = K4 + 'X' * (nrows * L - 97)
        rows = [padded[r*L:(r+1)*L] for r in range(nrows)]
        # ID each row by its quadgram score (or letter sum)
        row_scores = [sum(AZI.get(c, 0) for c in row) for row in rows]
        row_order = argsort(row_scores)
        candidate_ct = ''.join(rows[r] for r in row_order)
        candidate_ct = ''.join(c for c in candidate_ct if c != 'X')[:97]
        if len(candidate_ct) == 97:
            r = test_ct(candidate_ct, f"P_idbyrows_valsum_L{L}")
            results.append(r)

    # P5: Use extract as a transposition key for K4 in a different way
    # The extract (106 chars) defines a reading of the KA tableau
    # Treat extract positions as defining which K4 chars are "first layer" vs "second"
    # Layer split: extract chars that appear in K4 form one layer
    extract_set = set(GRILLE_EXTRACT)
    k4_set = set(K4)
    common = extract_set & k4_set
    only_k4 = k4_set - extract_set
    print(f"  Common chars (extract ∩ K4): {sorted(common)}", flush=True)
    print(f"  K4-only chars: {sorted(only_k4)}", flush=True)

    # Split K4 by presence in extract
    in_extract_pos = [i for i, c in enumerate(K4) if c in extract_set]
    not_in_extract_pos = [i for i, c in enumerate(K4) if c not in extract_set]
    print(f"  K4 positions in extract chars: {len(in_extract_pos)}, not: {len(not_in_extract_pos)}", flush=True)

    perm_P5a = in_extract_pos + not_in_extract_pos
    if validate_perm(perm_P5a):
        r = test_perm(perm_P5a, "P_split_by_extract_chars")
        results.append(r)

    perm_P5b = not_in_extract_pos + in_extract_pos
    if validate_perm(perm_P5b):
        r = test_perm(perm_P5b, "P_split_by_extract_chars_rev")
        results.append(r)

    report_best(results, "P")
    return results

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(f"\nK4: {K4}", flush=True)
    print(f"N={N}, len(GRILLE_EXTRACT)={len(GRILLE_EXTRACT)}", flush=True)
    print(f"HOLES: {len(HOLES)}", flush=True)
    print(f"KEYWORDS: {KEYWORDS}", flush=True)
    print(f"Output: {RESULTS_FILE}", flush=True)

    t_start = time.time()

    all_results = []

    # Run all approaches
    for approach_fn, name in [
        (approach_A, "A: Interleaved Streams"),
        (approach_B, "B: Grille Arithmetic"),
        (approach_C, "C: Self-Referential"),
        (approach_D, "D: K1-K3 as Key"),
        (approach_E, "E: Copper Plate Fold"),
        (approach_F, "F: Grille as Substitution Alpha"),
        (approach_G, "G: Grille Hole Coordinate Orderings"),
        (approach_H, "H: Clock Cipher"),
        (approach_I, "I: Morse / T-Position"),
        (approach_J, "J: IDBYROWS"),
        (approach_K, "K: Doubled-Letter Positions"),
        (approach_L, "L: KA-Index Mapping"),
        (approach_M, "M: Keyword Reverse Engineering"),
        (approach_N, "N: Novel Structural Permutations"),
        (approach_O, "O: Extract → 97-Perm Constructions"),
        (approach_P, "P: Combined / Double-Scramble"),
    ]:
        try:
            t0 = time.time()
            res = approach_fn()
            elapsed = time.time() - t0
            all_results.extend(r for r in (res or []) if r is not None)
            print(f"\n  [{name}] Done in {elapsed:.1f}s, tested {total_tested} unique CTs", flush=True)
        except Exception as e:
            print(f"\n  [{name}] ERROR: {e}", flush=True)
            import traceback
            traceback.print_exc()

    # Summary
    elapsed_total = time.time() - t_start
    print("\n" + "="*70, flush=True)
    print(f"DONE — Total time: {elapsed_total:.1f}s", flush=True)
    print(f"Total unique CTs tested: {total_tested}", flush=True)
    print(f"CRIB HITS: {len(HITS)}", flush=True)

    if HITS:
        print("\n*** CRIB HITS SUMMARY ***", flush=True)
        for h in HITS:
            print(f"  {h}", flush=True)
    else:
        # Print best scoring results
        valid = [r for r in all_results if r is not None and 'score' in r]
        if valid:
            top = sorted(valid, key=lambda r: r['score'], reverse=True)[:10]
            print(f"\nTop 10 results by quadgram score:", flush=True)
            for r in top:
                print(f"  {r['label']}: score={r['score']:.3f} key={r['key']} cipher={r['cipher']}", flush=True)
                print(f"    PT: {r['pt']}", flush=True)

    _rf.close()
    print(f"\nResults saved to {RESULTS_FILE}", flush=True)
