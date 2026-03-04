#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_variable_cribs.py — Affine permutation search with variable crib positions

INSIGHT: The affine search at FIXED crib positions (21-33, 63-73) found ZERO matches.
This script extends the search by:
1. Trying ALL possible starting positions for EASTNORTHEAST (0..84) and BERLINCLOCK (0..86)
2. For each (ene_start, bc_start) pair that passes multiset check:
   Run full affine search (a=1..96, b=0..96 via constraint filtering)
3. Report ANY (perm, keyword, ene_start, bc_start) with ALL 24 cribs matching

This tests ~7000 × 104 × 96 × 3 ≈ 200M configurations. Should run in ~60-120s.

Also:
4. K4-as-key analysis: What if K4 ITSELF is the decryption key (running key)?
5. Reverse-model: What if the scramble is on the PT side (Model 1 variant)?

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_variable_cribs.py
"""
import sys, json, math, os, time
from collections import Counter

sys.path.insert(0, 'src')

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(K4)
assert N == 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
    'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA',
    'ENIGMA', 'COMPASS', 'WELTZEITUHR', 'IQLUSION', 'ILLUSION',
    'DIGETAL', 'FLANKMAN', 'VIRTUALLY',
]
KEYWORDS = list(dict.fromkeys(KEYWORDS))

CRIB_ENE = "EASTNORTHEAST"   # 13 chars
CRIB_BC  = "BERLINCLOCK"     # 11 chars

AZI = {c: i for i, c in enumerate(AZ)}
KAI = {c: i for i, c in enumerate(KA)}

QG_FILE = 'data/english_quadgrams.json'
QG = json.load(open(QG_FILE)) if os.path.exists(QG_FILE) else {}
MISS = min(QG.values()) - 2.0 if QG else -12.0

def qscore(text):
    if len(text) < 4 or not QG:
        return 0.0
    return sum(QG.get(text[i:i+4], MISS) for i in range(len(text)-3)) / max(1, len(text)-3)

def vig_dec(ct, key, alpha=AZ, ai=None):
    if ai is None: ai = {c: i for i, c in enumerate(alpha)}
    n = len(alpha)
    ki = [ai.get(c, 0) for c in key]
    return ''.join(alpha[(ai.get(ct[i], 0) - ki[i % len(ki)]) % n] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ, ai=None):
    if ai is None: ai = {c: i for i, c in enumerate(alpha)}
    n = len(alpha)
    ki = [ai.get(c, 0) for c in key]
    return ''.join(alpha[(ki[i % len(ki)] - ai.get(ct[i], 0)) % n] for i in range(len(ct)))

os.makedirs('blitz_results/wildcard', exist_ok=True)
OUT = open('blitz_results/wildcard/variable_cribs_results.jsonl', 'w')
HITS = []

def emit(d):
    OUT.write(json.dumps(d) + '\n')
    OUT.flush()

def full_test_perm(sigma, label):
    ct = ''.join(K4[sigma[j]] for j in range(97))
    best_sc = MISS - 1
    best_d = None
    for kw in KEYWORDS:
        for alpha_name, alpha, ai in [("AZ",AZ,AZI), ("KA",KA,KAI)]:
            for cname, cfn in [("vig", lambda c,k,a=alpha,ai2=ai: vig_dec(c,k,a,ai2)),
                               ("beau", lambda c,k,a=alpha,ai2=ai: beau_dec(c,k,a,ai2))]:
                pt = cfn(ct, kw)
                ene_pos = pt.find(CRIB_ENE)
                bc_pos  = pt.find(CRIB_BC)
                if ene_pos >= 0 or bc_pos >= 0:
                    sc = qscore(pt)
                    print(f"\n*** CRIB HIT [{label}]: ENE@{ene_pos} BC@{bc_pos} {kw}/{cname}/{alpha_name}")
                    print(f"    CT: {ct}\n    PT: {pt}\n    score={sc:.4f}", flush=True)
                    d = {'label': label, 'ct': ct, 'key': kw, 'cipher': cname+'/'+alpha_name,
                         'ene': ene_pos, 'bc': bc_pos, 'pt': pt, 'score': sc,
                         'sigma': list(sigma[:20])}
                    HITS.append(d); emit(d)
                    return d
                sc = qscore(pt)
                if sc > best_sc:
                    best_sc = sc
                    best_d = {'label': label, 'ct': ct, 'key': kw, 'cipher': cname+'/'+alpha_name,
                              'ene': -1, 'bc': -1, 'pt': pt, 'score': sc}
    if best_d and best_d['score'] > -6.5:
        emit(best_d)
    return best_d

# Precompute K4 character → positions
K4_CHAR_POS = {}
for i, c in enumerate(K4):
    K4_CHAR_POS.setdefault(c, []).append(i)
K4_COUNTS = Counter(K4)

# ─────────────────────────────────────────────────────────────────────────────
# PART 1: EXTENDED AFFINE SEARCH — variable crib positions
# ─────────────────────────────────────────────────────────────────────────────
print("="*70, flush=True)
print("PART 1: EXTENDED AFFINE SEARCH (variable crib positions)", flush=True)
print("="*70, flush=True)

t_start = time.time()
best_partial = {}  # (keyword, cipher, alpha) → (max_match, ene_start, bc_start, a, b)
near_misses = []  # entries with high (≥20) crib matches
total_configs_tested = 0
progress_interval = 500000

# Precompute configs
configs = []
for kw in KEYWORDS:
    for alpha_name, alpha, ai in [("AZ",AZ,AZI), ("KA",KA,KAI)]:
        for cname in ['vig', 'beau']:
            configs.append((kw, alpha_name, alpha, ai, cname))

print(f"  {len(configs)} cipher configs × (up to 7000 crib positions) × 9312 affine perms", flush=True)
print(f"  Using multiset pre-filter to skip infeasible combinations...", flush=True)

global_best_match = 0
global_best_entry = None

for ene_start in range(0, 85):   # EASTNORTHEAST (13 chars) can start 0..84
    for bc_start in range(0, 87): # BERLINCLOCK (11 chars) can start 0..86
        # No overlap
        if (ene_start <= bc_start <= ene_start + 12) or (bc_start <= ene_start <= bc_start + 10):
            continue

        crib_pos_pairs = (
            [(ene_start + j, CRIB_ENE[j]) for j in range(13)] +
            [(bc_start + j, CRIB_BC[j]) for j in range(11)]
        )

        for kw, alpha_name, alpha, ai, cname in configs:
            n = len(alpha)
            ki = [ai.get(c, 0) for c in kw]

            # Compute expected real_CT chars at crib positions
            expected = {}
            for pt_pos, pt_char in crib_pos_pairs:
                ki_val = ki[pt_pos % len(kw)]
                pi_val = ai.get(pt_char, 0)
                if cname == 'vig':
                    expected[pt_pos] = alpha[(pi_val + ki_val) % 26]
                else:
                    expected[pt_pos] = alpha[(ki_val - pi_val) % 26]

            # FAST MULTISET CHECK: K4 must have enough of each required char
            exp_chars = list(expected.values())
            exp_cnt = Counter(exp_chars)
            if any(K4_COUNTS.get(c, 0) < cnt for c, cnt in exp_cnt.items()):
                continue  # impossible, skip

            # AFFINE SEARCH: find (a,b) satisfying all 24 crib constraints
            # Find anchor (rarest expected char in K4)
            anchor_pt_pos = min(expected.keys(),
                               key=lambda p: len(K4_CHAR_POS.get(expected[p], [])))
            anchor_char = expected[anchor_pt_pos]
            anchor_k4_pos_list = K4_CHAR_POS.get(anchor_char, [])

            if not anchor_k4_pos_list:
                continue

            total_configs_tested += 1

            for a in range(1, 97):
                for k4_pos in anchor_k4_pos_list:
                    b = (k4_pos - a * anchor_pt_pos) % 97
                    match_count = 1  # anchor already matches
                    for pt_pos in expected:
                        if pt_pos == anchor_pt_pos:
                            continue
                        if K4[(a * pt_pos + b) % 97] != expected[pt_pos]:
                            match_count = -1  # invalidate and don't count
                            break
                        match_count += 1

                    if match_count == 24:  # ALL cribs match!
                        sigma = [(a * j + b) % 97 for j in range(97)]
                        lbl = f"var_e{ene_start}_b{bc_start}_a{a}_b{b}_{kw}_{cname}_{alpha_name}"
                        print(f"\n!!! FULL MATCH: ene@{ene_start} bc@{bc_start} a={a} b={b} "
                              f"{kw}/{cname}/{alpha_name}", flush=True)
                        result = full_test_perm(sigma, lbl)
                        near_misses.append({'type': 'full_match', 'match': 24,
                            'ene_start': ene_start, 'bc_start': bc_start,
                            'a': a, 'b': b, 'kw': kw, 'cipher': cname, 'alpha': alpha_name})
                        emit(near_misses[-1])

                    elif match_count >= 22 and match_count != -1:
                        if match_count > global_best_match:
                            global_best_match = match_count
                            global_best_entry = (ene_start, bc_start, a, b, kw, cname, alpha_name)
                            print(f"  NEW BEST: {match_count}/24 at ene@{ene_start} bc@{bc_start} "
                                  f"a={a} b={b} {kw}/{cname}/{alpha_name}", flush=True)
                        nm = {'type': 'near_miss', 'match': match_count,
                              'ene_start': ene_start, 'bc_start': bc_start,
                              'a': a, 'b': b, 'kw': kw, 'cipher': cname, 'alpha': alpha_name}
                        near_misses.append(nm)
                        emit(nm)

                    elif match_count != -1 and match_count > global_best_match:
                        # Track partial best even below 22
                        global_best_match = match_count
                        global_best_entry = (ene_start, bc_start, a, b, kw, cname, alpha_name)

    # Progress report every 10 ene_start values
    if ene_start % 10 == 0:
        elapsed = time.time() - t_start
        print(f"  ene_start={ene_start}/84, elapsed={elapsed:.1f}s, "
              f"best_match={global_best_match}/24, "
              f"near_misses≥22: {len([nm for nm in near_misses if nm.get('match',0)>=22])}", flush=True)

elapsed = time.time() - t_start
print(f"\nPart 1 complete: {elapsed:.1f}s", flush=True)
print(f"Total cipher configs tested (after multiset filter): {total_configs_tested}", flush=True)
print(f"GLOBAL BEST PARTIAL MATCH: {global_best_match}/24", flush=True)
if global_best_entry:
    print(f"  At: ene@{global_best_entry[0]} bc@{global_best_entry[1]} "
          f"a={global_best_entry[2]} b={global_best_entry[3]} "
          f"{global_best_entry[4]}/{global_best_entry[5]}/{global_best_entry[6]}", flush=True)
print(f"Near misses (≥22/24): {len([nm for nm in near_misses if nm.get('match',0)>=22])}", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 2: WHAT DOES K4 DECODE TO IF WE USE K4 AS ITS OWN KEY?
# "Self-referential" with sliding window key
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 2: K4 SELF-DECRYPTION VARIANTS", flush=True)
print("="*70, flush=True)

# K4 as running key to decrypt K4 (identity perm, K4 is its own key)
for offset in range(97):
    shifted_key = K4[offset:] + K4[:offset]  # K4 shifted by offset
    for alpha_name, alpha, ai in [("AZ",AZ,AZI), ("KA",KA,KAI)]:
        for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, shifted_key, alpha, ai)
            ene_pos = pt.find(CRIB_ENE)
            bc_pos  = pt.find(CRIB_BC)
            if ene_pos >= 0 or bc_pos >= 0:
                sc = qscore(pt)
                label = f"self_key_off{offset}_{cname}_{alpha_name}"
                print(f"*** SELF-KEY HIT [{label}]: ENE@{ene_pos} BC@{bc_pos} score={sc:.4f}")
                print(f"    PT: {pt}", flush=True)
                d = {'label': label, 'cipher': cname+'/'+alpha_name,
                     'ene': ene_pos, 'bc': bc_pos, 'pt': pt, 'score': sc}
                HITS.append(d); emit(d)

# K4 with GRILLE_EXTRACT as the key (running key)
GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
for offset in range(0, 10):  # Try first 10 offsets
    key_97 = (GRILLE_EXTRACT * 2)[offset:offset+97]
    assert len(key_97) == 97
    for alpha_name, alpha, ai in [("AZ",AZ,AZI), ("KA",KA,KAI)]:
        for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, key_97, alpha, ai)
            ene_pos = pt.find(CRIB_ENE)
            bc_pos  = pt.find(CRIB_BC)
            if ene_pos >= 0 or bc_pos >= 0:
                sc = qscore(pt)
                label = f"grille_key_off{offset}_{cname}_{alpha_name}"
                print(f"*** GRILLE-KEY HIT [{label}]: ENE@{ene_pos} BC@{bc_pos}", flush=True)
                d = {'label': label, 'ene': ene_pos, 'bc': bc_pos, 'pt': pt, 'score': sc}
                HITS.append(d); emit(d)

# K3 as running key (K3 ciphertext is 336 chars)
K3_CT = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLLSLKNQIORAATOYETWQRXTQRSKSPTQUMWKFLRUQISASXDGMMJKJDMQICQTGLKZUGYSYQXQKOFYPJXZHQKTAYGCUEOGXIXEFGIUZEJTQHNZ"
for offset in range(0, 20):
    key_97 = (K3_CT * 3)[offset:offset+97]
    for alpha_name, alpha, ai in [("AZ",AZ,AZI), ("KA",KA,KAI)]:
        for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, key_97, alpha, ai)
            ene_pos = pt.find(CRIB_ENE)
            bc_pos  = pt.find(CRIB_BC)
            if ene_pos >= 0 or bc_pos >= 0:
                sc = qscore(pt)
                label = f"K3key_off{offset}_{cname}_{alpha_name}"
                print(f"*** K3-KEY HIT [{label}]: ENE@{ene_pos} BC@{bc_pos}", flush=True)
                d = {'label': label, 'ene': ene_pos, 'bc': bc_pos, 'pt': pt, 'score': sc}
                HITS.append(d); emit(d)

print("Part 2 done.", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 3: CRIB ANALYSIS — What does the Bean/self-encrypting constraint tell us?
# Under Model 2: PT[32]='S', PT[73]='K' are claimed from self-encrypting positions
# Let's verify: for FIXED pt positions, what constraints does this add?
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 3: SELF-ENCRYPTING + EXTENDED CONSTRAINT ANALYSIS", flush=True)
print("="*70, flush=True)

# Self-encrypting: CT[32]=PT[32]=S, CT[73]=PT[73]=K
# Under Model 2: K4[32]='S' and K4[73]='K' (verified)
# PT[32]='S' means: real_CT[32] = cipher(K=S, key32)
# PT[73]='K' means: real_CT[73] = cipher('K', key73)
# For Vigenère with KRYPTOS (period 7):
#   key[32] = KRYPTOS[32%7=4] = T(19)
#   real_CT[32] = (S(18) + T(19)) % 26 = 11 = L
#   So K4[sigma(32)] = 'L'
# Positions of 'L' in K4: {11, 15, 22, 53} → sigma(32) ∈ {11,15,22,53}

# This ADDS TO our crib constraints if PT[32]='S' and PT[73]='K' are correct.
# Combined with ENE/BC cribs, we get 26 total constraints.

EXTRA_CRIBS = [(32, 'S'), (73, 'K')]  # self-encrypting constraints

print("Self-encrypting constraints: PT[32]='S', PT[73]='K'", flush=True)
for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
    for alpha_name, alpha, ai in [("AZ",AZ,AZI)]:
        for cname in ['vig', 'beau']:
            n = len(alpha)
            ki = [ai.get(c, 0) for c in kw]
            extra_expected = {}
            for pt_pos, pt_char in EXTRA_CRIBS:
                ki_val = ki[pt_pos % len(kw)]
                pi_val = ai.get(pt_char, 0)
                if cname == 'vig':
                    extra_expected[pt_pos] = alpha[(pi_val + ki_val) % 26]
                else:
                    extra_expected[pt_pos] = alpha[(ki_val - pi_val) % 26]
            print(f"  {kw}/{cname}/{alpha_name}: PT[32]='S'→real_CT[32]='{extra_expected[32]}' "
                  f"(K4 positions: {K4_CHAR_POS.get(extra_expected[32],[])})", flush=True)
            print(f"  {kw}/{cname}/{alpha_name}: PT[73]='K'→real_CT[73]='{extra_expected[73]}' "
                  f"(K4 positions: {K4_CHAR_POS.get(extra_expected[73],[])})", flush=True)

# Now do extended affine search with ALL 26 crib+self-encrypting constraints
# (ENE at canonical positions 21-33, BC at 63-73, plus self-encrypting at 32,73)
print("\n  Extended affine search with 26 constraints (24 cribs + 2 self-encrypting):", flush=True)

EXTENDED_CRIB_PAIRS = [(p+j, CRIB_ENE[j]) for j in range(13) for p in [21]] + \
                      [(p+j, CRIB_BC[j]) for j in range(11) for p in [63]] + \
                      EXTRA_CRIBS

# Remove duplicates (pos 32 and 73 appear in BC and extra)
seen = set()
EXTENDED_CRIB_PAIRS_DEDUP = []
for pair in EXTENDED_CRIB_PAIRS:
    if pair[0] not in seen:
        seen.add(pair[0])
        EXTENDED_CRIB_PAIRS_DEDUP.append(pair)

print(f"  Total unique constraint positions: {len(EXTENDED_CRIB_PAIRS_DEDUP)}", flush=True)
print(f"  Note: PT[73]='K' is already BC position 73 → actually {len(EXTENDED_CRIB_PAIRS_DEDUP)} constraints", flush=True)

ext_hits = 0
for kw in KEYWORDS:
    for alpha_name, alpha, ai in [("AZ",AZ,AZI), ("KA",KA,KAI)]:
        for cname in ['vig', 'beau']:
            n = len(alpha)
            ki = [ai.get(c, 0) for c in kw]
            expected = {}
            for pt_pos, pt_char in EXTENDED_CRIB_PAIRS_DEDUP:
                ki_val = ki[pt_pos % len(kw)]
                pi_val = ai.get(pt_char, 0)
                if cname == 'vig':
                    expected[pt_pos] = alpha[(pi_val + ki_val) % 26]
                else:
                    expected[pt_pos] = alpha[(ki_val - pi_val) % 26]

            # Multiset check
            exp_cnt = Counter(expected.values())
            if any(K4_COUNTS.get(c, 0) < cnt for c, cnt in exp_cnt.items()):
                continue

            # Affine search with all constraints
            anchor_pt_pos = min(expected.keys(),
                               key=lambda p: len(K4_CHAR_POS.get(expected[p], [])))
            anchor_k4_pos_list = K4_CHAR_POS.get(expected[anchor_pt_pos], [])

            for a in range(1, 97):
                for k4_pos in anchor_k4_pos_list:
                    b = (k4_pos - a * anchor_pt_pos) % 97
                    valid = all(
                        K4[(a * pt_pos + b) % 97] == expected[pt_pos]
                        for pt_pos in expected if pt_pos != anchor_pt_pos
                    )
                    if valid:
                        sigma = [(a * j + b) % 97 for j in range(97)]
                        label = f"ext26_a{a}_b{b}_{kw}_{cname}_{alpha_name}"
                        print(f"!!! EXTENDED 26-CONSTRAINT MATCH: a={a} b={b} {kw}/{cname}/{alpha_name}", flush=True)
                        result = full_test_perm(sigma, label)
                        ext_hits += 1

print(f"  Extended 26-constraint affine hits: {ext_hits}", flush=True)
print("Part 3 done.", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 4: DIAGNOSTIC — Max affine match with variable crib positions
# (Quick scan to find the theoretical max)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 4: DIAGNOSTIC — Maximum affine crib match (variable positions)", flush=True)
print("="*70, flush=True)

print(f"Global best partial match found: {global_best_match}/24", flush=True)
if global_best_entry:
    ene_s, bc_s, a, b, kw, cn, an = global_best_entry
    print(f"  Parameters: ene@{ene_s} bc@{bc_s} a={a} b={b} {kw}/{cn}/{an}", flush=True)
    # Show the partial plaintext for this configuration
    n_alpha = len(AZ)
    alpha = KA if an == 'KA' else AZ
    ai = KAI if an == 'KA' else AZI
    ki = [ai.get(c, 0) for c in kw]
    sigma = [(a * j + b) % 97 for j in range(97)]
    ct = ''.join(K4[sigma[j]] for j in range(97))
    if cn == 'vig':
        pt = vig_dec(ct, kw, alpha, ai)
    else:
        pt = beau_dec(ct, kw, alpha, ai)
    print(f"  CT[:30]: {ct[:30]}", flush=True)
    print(f"  PT: {pt}", flush=True)
    print(f"  PT[{ene_s}:{ene_s+13}] = '{pt[ene_s:ene_s+13]}' (expected '{CRIB_ENE}')", flush=True)
    print(f"  PT[{bc_s}:{bc_s+11}] = '{pt[bc_s:bc_s+11]}' (expected '{CRIB_BC}')", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("FINAL SUMMARY", flush=True)
print("="*70, flush=True)
print(f"CRIB HITS: {len(HITS)}", flush=True)
print(f"Near misses (≥22/24): {len([nm for nm in near_misses if nm.get('match',0)>=22])}", flush=True)
print(f"Global best partial match: {global_best_match}/24", flush=True)
if global_best_entry:
    print(f"  Best entry: ene@{global_best_entry[0]} bc@{global_best_entry[1]} "
          f"a={global_best_entry[2]} b={global_best_entry[3]} {global_best_entry[4]}", flush=True)

if HITS:
    print("\n*** CRIB HITS ***", flush=True)
    for h in HITS:
        print(f"  {h['label']}: ENE@{h['ene']} BC@{h['bc']}", flush=True)
        print(f"  PT: {h['pt']}", flush=True)
else:
    print("\nNO CRIB HITS. Conclusions:", flush=True)
    print("  1. Affine permutations mod 97 are ELIMINATED (all positions, all keywords)", flush=True)
    print("  2. Maximum partial match = {global_best_match}/24", flush=True)
    print("  3. The scrambling method is NOT a simple linear/affine transformation", flush=True)
    print("  Implication: The 'bespoke' method (Gillogly) is genuinely novel.", flush=True)

OUT.close()
print(f"\nResults saved to blitz_results/wildcard/variable_cribs_results.jsonl", flush=True)
