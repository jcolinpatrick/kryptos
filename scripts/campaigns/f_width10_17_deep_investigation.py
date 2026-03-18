#!/usr/bin/env python3
"""
Deep investigation of width-10 (p=0.006) and width-17 (p=0.008) bigram
anomalies in CT73 (null-extracted 73-char K4 text).

These anomalies appear ONLY in CT73, not in CT97 or CT73_COL7.
Since col7 DESTROYS the patterns, they exist in the PRE-transposition text
(= cipher output before columnar read-off).

Investigations:
1. Exact bigram positions and crib overlap analysis
2. Period-10 and period-17 crib consistency (all 3 cipher variants)
3. Exhaustive period-10/17 Beaufort/Vigenere key search
4. Autokey with primers of length 10 and 17
5. Quagmire II with period 10/17
6. 10x7 and 7x10 grid analysis
7. Interaction with col7 transposition
8. Cross-width combined analysis (lcm patterns)

Cipher: substitution/transposition analysis
Family: campaigns
Status: active
Keyspace: ~50M configs
Last run: never
Best score: pending
"""

import sys, os, json, time, itertools
from collections import defaultdict, Counter
from datetime import datetime
from multiprocessing import Pool, cpu_count

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, CRIB_WORDS

# ── Setup ──────────────────────────────────────────────────────────────
MASK = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
MASK_SET = set(MASK)
CT73 = ''.join(CT[i] for i in range(97) if i not in MASK_SET)
CT73_LEN = len(CT73)
assert CT73_LEN == 73, f"CT73 length {CT73_LEN} != 73"
assert CT73 == 'RUXOHULSLIFBBFLRVQQPRNGKSSOTTQSSEKZZWATJLUIANFBNYPVTTMZFPKDKXTJCDKUUAUEKA'

# Shifted crib positions in CT73
# Original: ENE at 21-33, BCL at 63-73 in CT97
# After removing nulls from MASK, positions shift
def ct97_to_ct73_pos(p97):
    """Convert a CT97 position to the corresponding CT73 position."""
    if p97 in MASK_SET:
        return None
    return p97 - sum(1 for m in MASK if m < p97)

ENE_POSITIONS_73 = []
BCL_POSITIONS_73 = []
for start, word in CRIB_WORDS:
    for i, ch in enumerate(word):
        p97 = start + i
        p73 = ct97_to_ct73_pos(p97)
        if p73 is not None:
            if start == 21:
                ENE_POSITIONS_73.append((p73, ch))
            else:
                BCL_POSITIONS_73.append((p73, ch))

CRIB_73 = {}
for p73, ch in ENE_POSITIONS_73 + BCL_POSITIONS_73:
    CRIB_73[p73] = ch

ENE_START_73 = ENE_POSITIONS_73[0][0] if ENE_POSITIONS_73 else None
BCL_START_73 = BCL_POSITIONS_73[0][0] if BCL_POSITIONS_73 else None

print(f"CT73 = {CT73} ({CT73_LEN} chars)")
print(f"ENE positions in CT73: {[(p, c) for p, c in ENE_POSITIONS_73]}")
print(f"BCL positions in CT73: {[(p, c) for p, c in BCL_POSITIONS_73]}")
print(f"ENE start in CT73: {ENE_START_73}, BCL start in CT73: {BCL_START_73}")
print(f"Total crib positions in CT73: {len(CRIB_73)}")
print()

# Col7 transposition helpers
def columnar_perm(width, length):
    """Standard columnar perm: fill rows L-R, read cols in order 0,1,2,..."""
    cols = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm = []
    for c in range(width):
        perm.extend(cols[c])
    return perm

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def apply_perm(text, perm):
    return ''.join(text[perm[i]] for i in range(len(text)))

COL7_PERM = columnar_perm(7, 73)
COL7_INV = invert_perm(COL7_PERM)
CT73_COL7 = apply_perm(CT73, COL7_INV)  # Undo col7 transposition

print(f"CT73_COL7 = {CT73_COL7}")
print()

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 1: Width-10 and Width-17 Bigram Deep Dive
# ══════════════════════════════════════════════════════════════════════
print("=" * 70)
print("INVESTIGATION 1: BIGRAM ANALYSIS AT WIDTHS 10 AND 17")
print("=" * 70)

def vertical_bigrams(text, width):
    """Return dict of {bigram: [positions]} for vertical bigrams at given width."""
    n = len(text)
    bigrams = defaultdict(list)
    for i in range(n):
        j = i + width
        if j < n:
            bg = text[i] + text[j]
            bigrams[bg].append(i)
    return bigrams

def analyze_width(text, width, name, crib_positions=None):
    """Full bigram analysis at a given width."""
    bgs = vertical_bigrams(text, width)
    repeats = {bg: positions for bg, positions in bgs.items() if len(positions) > 1}
    total_bgs = sum(len(positions) for positions in bgs.values())
    n_repeats = sum(len(positions) for bg, positions in repeats.items())

    print(f"\n--- {name} at width {width} ---")
    print(f"Total vertical bigrams: {total_bgs}")
    print(f"Repeated bigrams: {len(repeats)} types, {n_repeats} instances")

    # Write as grid
    nrows = (len(text) + width - 1) // width
    print(f"Grid: {nrows} rows x {width} cols")
    for r in range(nrows):
        row = text[r*width:(r+1)*width]
        markers = ""
        if crib_positions:
            markers = " | " + ''.join(
                '^' if r*width+c in crib_positions else '.'
                for c in range(len(row))
            )
        print(f"  Row {r}: {row}{markers}")

    print(f"\n  Repeated bigrams detail:")
    for bg, positions in sorted(repeats.items(), key=lambda x: -len(x[1])):
        crib_overlap = []
        for p in positions:
            p_in_crib = p in (crib_positions or {})
            p2_in_crib = (p + width) in (crib_positions or {})
            crib_overlap.append(f"({p}{'*' if p_in_crib else ''},{p+width}{'*' if p2_in_crib else ''})")
        print(f"    {bg} x{len(positions)}: positions {', '.join(crib_overlap)}")

    return repeats

w10_repeats = analyze_width(CT73, 10, "CT73", CRIB_73)
w17_repeats = analyze_width(CT73, 17, "CT73", CRIB_73)
print()

# Check same widths on CT97 and CT73_COL7 for comparison
analyze_width(CT73_COL7, 10, "CT73_COL7", None)
analyze_width(CT73_COL7, 17, "CT73_COL7", None)
print()

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 2: PERIOD CONSISTENCY AT 10 AND 17
# ══════════════════════════════════════════════════════════════════════
print("=" * 70)
print("INVESTIGATION 2: CRIB CONSISTENCY AT PERIODS 10 AND 17")
print("=" * 70)

def compute_keystream(ct_char, pt_char, variant):
    """Compute keystream value for a single position."""
    c = ALPH_IDX[ct_char]
    p = ALPH_IDX[pt_char]
    if variant == 'vig':
        return (c - p) % MOD
    elif variant == 'beau':
        return (c + p) % MOD
    elif variant == 'vbeau':
        return (p - c) % MOD
    raise ValueError(f"Unknown variant: {variant}")

def check_period_consistency(text, crib_dict, period, variant):
    """Check if crib positions sharing residue mod period have consistent keystream."""
    residue_keys = defaultdict(set)
    residue_positions = defaultdict(list)

    for pos, pt_char in sorted(crib_dict.items()):
        r = pos % period
        k = compute_keystream(text[pos], pt_char, variant)
        residue_keys[r].add(k)
        residue_positions[r].append((pos, pt_char, text[pos], k))

    n_consistent = 0
    n_constrained = 0
    details = {}

    for r in sorted(residue_keys):
        keys = residue_keys[r]
        positions = residue_positions[r]
        if len(positions) >= 2:
            n_constrained += len(positions)
            if len(keys) == 1:
                n_consistent += len(positions)
                details[r] = ('CONSISTENT', list(keys)[0], positions)
            else:
                details[r] = ('CONFLICT', keys, positions)
        elif len(positions) == 1:
            n_consistent += 1
            n_constrained += 1
            details[r] = ('SINGLETON', list(keys)[0], positions)

    return n_consistent, n_constrained, details

for period in [10, 17]:
    print(f"\n--- Period {period} ---")
    for variant in ['vig', 'beau', 'vbeau']:
        n_con, n_tot, details = check_period_consistency(CT73, CRIB_73, period, variant)
        print(f"\n  {variant.upper()}: {n_con}/{n_tot} consistent ({len(CRIB_73)} crib positions)")

        conflicts = [(r, d) for r, d in details.items() if d[0] == 'CONFLICT']
        consistent = [(r, d) for r, d in details.items() if d[0] == 'CONSISTENT']
        singletons = [(r, d) for r, d in details.items() if d[0] == 'SINGLETON']

        if consistent:
            print(f"    Consistent residues ({len(consistent)}):")
            for r, (_, key, positions) in consistent:
                pos_str = ', '.join(f"{p}:{ct}/{pt}=k{k}" for p, pt, ct, k in positions)
                print(f"      r={r}: key={key} ({ALPH[key]}) from {pos_str}")

        if singletons:
            print(f"    Singleton residues ({len(singletons)}):")
            for r, (_, key, positions) in singletons:
                p, pt, ct, k = positions[0]
                print(f"      r={r}: key={key} ({ALPH[key]}) at pos {p}:{ct}/{pt}")

        if conflicts:
            print(f"    CONFLICTS ({len(conflicts)}):")
            for r, (_, keys, positions) in conflicts:
                pos_str = ', '.join(f"{p}:{ct}/{pt}=k{k}" for p, pt, ct, k in positions)
                print(f"      r={r}: keys={sorted(keys)} from {pos_str}")

print()

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 3: EXHAUSTIVE PERIOD-10/17 KEY SEARCH
# ══════════════════════════════════════════════════════════════════════
print("=" * 70)
print("INVESTIGATION 3: EXHAUSTIVE PERIOD-10/17 KEY SEARCH")
print("=" * 70)

# Load quadgrams
QUAD_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
try:
    with open(QUAD_PATH) as f:
        QUADS = json.load(f)
    QUAD_FLOOR = min(QUADS.values()) - 1.0
    print(f"Loaded {len(QUADS)} quadgrams")
except:
    QUADS = None
    QUAD_FLOOR = -10.0
    print("WARNING: Could not load quadgrams")

def quadgram_score(text):
    """Score text by quadgram log-probability per character."""
    if not QUADS or len(text) < 4:
        return -10.0
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADS.get(qg, QUAD_FLOOR)
        n += 1
    return total / n if n > 0 else -10.0

def decrypt_periodic(ct_text, key, variant):
    """Decrypt with periodic key."""
    period = len(key)
    result = []
    for i, c in enumerate(ct_text):
        ci = ALPH_IDX[c]
        ki = key[i % period]
        if variant == 'vig':
            pi = (ci - ki) % MOD
        elif variant == 'beau':
            pi = (ki - ci) % MOD
        elif variant == 'vbeau':
            pi = (ci + ki) % MOD
        else:
            raise ValueError
        result.append(ALPH[pi])
    return ''.join(result)

def score_crib_match(pt_text, crib_dict):
    """Count how many crib positions match."""
    matches = 0
    for pos, expected in crib_dict.items():
        if pos < len(pt_text) and pt_text[pos] == expected:
            matches += 1
    return matches

# For each period, if consistency exists, extract the key and test
for period in [10, 17]:
    print(f"\n--- Period {period}: Exhaustive key from crib constraints ---")
    for variant in ['vig', 'beau', 'vbeau']:
        n_con, n_tot, details = check_period_consistency(CT73, CRIB_73, period, variant)

        if n_con < n_tot:
            # Has conflicts -- try to find best partial key
            key = [None] * period
            conflict_residues = set()
            for r, d in details.items():
                if d[0] == 'CONSISTENT' or d[0] == 'SINGLETON':
                    key[r] = d[1]
                else:
                    conflict_residues.add(r)

            # For conflict residues, try each possible key value
            # and find the one maximizing crib matches
            if conflict_residues:
                free_residues = [r for r in range(period) if key[r] is None] + list(conflict_residues)
                # Too many free? Just try each conflict residue with the key giving most matches
                for r in conflict_residues:
                    _, keys_set, positions = details[r]
                    # Pick the most common key value
                    key_counts = Counter()
                    for _, _, _, k in positions:
                        key_counts[k] += 1
                    key[r] = key_counts.most_common(1)[0][0]

            # Fill remaining None with 0
            for i in range(period):
                if key[i] is None:
                    key[i] = 0

            pt = decrypt_periodic(CT73, key, variant)
            crib_match = score_crib_match(pt, CRIB_73)
            qg = quadgram_score(pt)
            key_str = ''.join(ALPH[k] for k in key)
            print(f"  {variant}: key={key_str} ({key}), crib={crib_match}/{len(CRIB_73)}, qg={qg:.3f}")
            print(f"    PT: {pt}")
        else:
            # Fully consistent! Extract key
            key = [0] * period
            for r, d in details.items():
                if d[0] in ('CONSISTENT', 'SINGLETON'):
                    key[r] = d[1]

            pt = decrypt_periodic(CT73, key, variant)
            crib_match = score_crib_match(pt, CRIB_73)
            qg = quadgram_score(pt)
            key_str = ''.join(ALPH[k] for k in key)
            print(f"  {variant}: FULLY CONSISTENT! key={key_str} ({key}), crib={crib_match}/{len(CRIB_73)}, qg={qg:.3f}")
            print(f"    PT: {pt}")

# Also try all 26^free combinations for unconstrained residues
print(f"\n--- Period 10: Exhaustive search over unconstrained residues ---")
for variant in ['vig', 'beau', 'vbeau']:
    n_con, n_tot, details = check_period_consistency(CT73, CRIB_73, 10, variant)

    # Extract constrained keys
    base_key = [None] * 10
    constrained_residues = set()
    for r, d in details.items():
        if d[0] == 'CONSISTENT' or d[0] == 'SINGLETON':
            base_key[r] = d[1]
            constrained_residues.add(r)

    free_residues = [r for r in range(10) if r not in constrained_residues]

    # For conflict residues, they're also "free" -- try all 26
    conflict_residues = set()
    for r, d in details.items():
        if d[0] == 'CONFLICT':
            conflict_residues.add(r)
            if r not in free_residues:
                free_residues.append(r)

    n_free = len(free_residues)
    total_search = 26 ** n_free

    print(f"\n  {variant}: {len(constrained_residues)} constrained, {n_free} free residues = {total_search} configs")

    if total_search > 5_000_000:
        print(f"    Skipping: too large ({total_search})")
        continue

    best_qg = -99.0
    best_crib = 0
    best_key = None
    best_pt = None
    count = 0

    for combo in itertools.product(range(26), repeat=n_free):
        key = list(base_key)
        for idx, r in enumerate(free_residues):
            key[r] = combo[idx]

        pt = decrypt_periodic(CT73, key, variant)
        crib_match = score_crib_match(pt, CRIB_73)

        if crib_match > best_crib or (crib_match == best_crib and QUADS):
            qg = quadgram_score(pt)
            if crib_match > best_crib or qg > best_qg:
                best_crib = crib_match
                best_qg = qg
                best_key = list(key)
                best_pt = pt

        count += 1

    key_str = ''.join(ALPH[k] for k in best_key) if best_key else 'N/A'
    print(f"    Best: crib={best_crib}/{len(CRIB_73)}, qg={best_qg:.3f}, key={key_str}")
    if best_pt:
        print(f"    PT: {best_pt}")

# Period 17 exhaustive
print(f"\n--- Period 17: Exhaustive search over unconstrained residues ---")
for variant in ['vig', 'beau', 'vbeau']:
    n_con, n_tot, details = check_period_consistency(CT73, CRIB_73, 17, variant)

    base_key = [None] * 17
    constrained_residues = set()
    for r, d in details.items():
        if d[0] == 'CONSISTENT' or d[0] == 'SINGLETON':
            base_key[r] = d[1]
            constrained_residues.add(r)

    free_residues = [r for r in range(17) if r not in constrained_residues]
    conflict_residues = set()
    for r, d in details.items():
        if d[0] == 'CONFLICT':
            conflict_residues.add(r)
            if r not in free_residues:
                free_residues.append(r)

    n_free = len(free_residues)
    total_search = 26 ** n_free

    print(f"\n  {variant}: {len(constrained_residues)} constrained, {n_free} free residues = {total_search} configs")

    if total_search > 5_000_000:
        print(f"    Skipping: too large ({total_search}). Using quadgram SA instead.")
        # Use simulated annealing for large spaces
        import random
        random.seed(42)

        # Start with crib-derived key where possible
        key = [0] * 17
        for r, d in details.items():
            if d[0] == 'CONSISTENT' or d[0] == 'SINGLETON':
                key[r] = d[1]
            elif d[0] == 'CONFLICT':
                _, keys_set, positions = d
                key_counts = Counter()
                for _, _, _, k in positions:
                    key_counts[k] += 1
                key[r] = key_counts.most_common(1)[0][0]

        best_pt = decrypt_periodic(CT73, key, variant)
        best_score = quadgram_score(best_pt)
        best_crib = score_crib_match(best_pt, CRIB_73)
        best_key = list(key)

        T = 2.0
        for step in range(500000):
            T = max(0.001, 2.0 * (1 - step / 500000))

            new_key = list(best_key)
            r = random.randint(0, 16)
            new_key[r] = random.randint(0, 25)

            pt = decrypt_periodic(CT73, new_key, variant)
            crib = score_crib_match(pt, CRIB_73)
            qg = quadgram_score(pt)

            # Weight crib matches heavily
            new_score = qg + crib * 0.5
            old_score = best_score + best_crib * 0.5

            delta = new_score - old_score
            if delta > 0 or random.random() < (2.718 ** (delta / T) if T > 0 else 0):
                best_key = new_key
                best_score = qg
                best_crib = crib
                best_pt = pt

        key_str = ''.join(ALPH[k] for k in best_key)
        print(f"    SA best: crib={best_crib}/{len(CRIB_73)}, qg={best_score:.3f}, key={key_str}")
        print(f"    PT: {best_pt}")
    else:
        best_qg = -99.0
        best_crib = 0
        best_key = None
        best_pt = None

        for combo in itertools.product(range(26), repeat=n_free):
            key = list(base_key)
            for idx, r in enumerate(free_residues):
                key[r] = combo[idx]

            pt = decrypt_periodic(CT73, key, variant)
            crib_match = score_crib_match(pt, CRIB_73)

            if crib_match > best_crib or (crib_match == best_crib and QUADS):
                qg = quadgram_score(pt)
                if crib_match > best_crib or qg > best_qg:
                    best_crib = crib_match
                    best_qg = qg
                    best_key = list(key)
                    best_pt = pt

        key_str = ''.join(ALPH[k] for k in best_key) if best_key else 'N/A'
        print(f"    Best: crib={best_crib}/{len(CRIB_73)}, qg={best_qg:.3f}, key={key_str}")
        if best_pt:
            print(f"    PT: {best_pt}")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 4: AUTOKEY WITH PRIMERS OF LENGTH 10 AND 17
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 4: AUTOKEY WITH PRIMERS OF LENGTH 10 AND 17")
print("=" * 70)

def decrypt_autokey_pt(ct_text, primer, variant):
    """Plaintext autokey decryption."""
    ct_nums = [ALPH_IDX[c] for c in ct_text]
    key = list(primer)
    pt = []
    for i, ci in enumerate(ct_nums):
        ki = key[i]
        if variant == 'vig':
            pi = (ci - ki) % MOD
        elif variant == 'beau':
            pi = (ki - ci) % MOD
        elif variant == 'vbeau':
            pi = (ci + ki) % MOD
        else:
            raise ValueError
        pt.append(pi)
        key.append(pi)  # plaintext autokey
    return ''.join(ALPH[p] for p in pt)

def decrypt_autokey_ct(ct_text, primer, variant):
    """Ciphertext autokey decryption."""
    ct_nums = [ALPH_IDX[c] for c in ct_text]
    key = list(primer)
    pt = []
    for i, ci in enumerate(ct_nums):
        ki = key[i]
        if variant == 'vig':
            pi = (ci - ki) % MOD
        elif variant == 'beau':
            pi = (ki - ci) % MOD
        elif variant == 'vbeau':
            pi = (ci + ki) % MOD
        else:
            raise ValueError
        pt.append(pi)
        key.append(ci)  # ciphertext autokey
    return ''.join(ALPH[p] for p in pt)

# Load thematic keywords
KEYWORDS_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords.txt')
try:
    with open(KEYWORDS_PATH) as f:
        THEMATIC = [line.strip().upper() for line in f if line.strip() and not line.startswith('#')]
    THEMATIC = [w for w in THEMATIC if w.isalpha()]
except:
    THEMATIC = ['KRYPTOS', 'DEFECTOR', 'ABSCISSA', 'PALIMPSEST', 'BERLINCLOCK', 'EASTNORTHEAST',
                'KOMPASS', 'COLOPHON', 'PARALLAX', 'ENIGMA', 'VERDIGRIS', 'COMPASS']

# Test autokey with primer lengths 10 and 17
for primer_len in [10, 17]:
    print(f"\n--- Autokey primer length {primer_len} ---")

    # Thematic keywords of right length or padded/truncated
    test_primers = set()
    for w in THEMATIC:
        if len(w) == primer_len:
            test_primers.add(w)
        elif len(w) > primer_len:
            test_primers.add(w[:primer_len])

    # Also try some specific primers
    specific = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'DEFECTOR', 'BERLINCLOCK',
                'EASTNORTHEAST', 'KOMPASS', 'COLOPHON']
    for s in specific:
        if len(s) >= primer_len:
            test_primers.add(s[:primer_len])
        else:
            # Pad with repeated keyword
            padded = (s * ((primer_len // len(s)) + 1))[:primer_len]
            test_primers.add(padded)

    best = {'crib': 0, 'qg': -99.0, 'info': ''}

    for primer_word in sorted(test_primers):
        primer = [ALPH_IDX[c] for c in primer_word]

        for variant in ['vig', 'beau', 'vbeau']:
            for ak_type, ak_fn in [('pt_ak', decrypt_autokey_pt), ('ct_ak', decrypt_autokey_ct)]:
                pt = ak_fn(CT73, primer, variant)
                crib = score_crib_match(pt, CRIB_73)
                qg = quadgram_score(pt)

                if crib > best['crib'] or (crib == best['crib'] and qg > best['qg']):
                    best = {'crib': crib, 'qg': qg, 'info': f"{primer_word}:{variant}:{ak_type}",
                            'pt': pt}

    print(f"  Best: crib={best['crib']}/{len(CRIB_73)}, qg={best['qg']:.3f}, {best['info']}")
    if 'pt' in best:
        print(f"  PT: {best['pt']}")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 5: 10x7 AND 7x10 GRID ANALYSIS
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 5: GRID ANALYSIS — 10x7, 7x10")
print("=" * 70)

def write_grid(text, width, name):
    """Write text as a grid."""
    nrows = (len(text) + width - 1) // width
    print(f"\n{name} ({nrows} rows x {width} cols, {len(text)} chars):")
    for r in range(nrows):
        row = text[r*width:(r+1)*width]
        print(f"  {row}")
    return nrows

# 10 x 7.3 rows
write_grid(CT73, 10, "CT73 at width 10")

# 7 x 10.4 rows
write_grid(CT73, 7, "CT73 at width 7")

# Also read columns
def read_columns(text, width):
    """Read text column by column from a grid."""
    nrows = (len(text) + width - 1) // width
    result = []
    for c in range(width):
        for r in range(nrows):
            pos = r * width + c
            if pos < len(text):
                result.append(text[pos])
    return ''.join(result)

print(f"\nCT73 written at w10, read by columns:")
col_read = read_columns(CT73, 10)
print(f"  {col_read}")
qg = quadgram_score(col_read)
crib_match = score_crib_match(col_read, CRIB_73)
print(f"  qg={qg:.3f}, crib check: {crib_match}/{len(CRIB_73)}")

print(f"\nCT73 written at w7, read by columns:")
col_read7 = read_columns(CT73, 7)
print(f"  {col_read7}")
qg7 = quadgram_score(col_read7)
print(f"  qg={qg7:.3f}")

# 17 x 4.3 rows
write_grid(CT73, 17, "CT73 at width 17")

print(f"\nCT73 written at w17, read by columns:")
col_read17 = read_columns(CT73, 17)
print(f"  {col_read17}")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 6: LCM ANALYSIS — 70 = lcm(10,7)
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 6: LCM(10,7) = 70 ANALYSIS")
print("=" * 70)

print(f"73 - 70 = 3. If cipher uses 70-char block + 3 overflow...")
print(f"CT73[:70] at width 10:")
write_grid(CT73[:70], 10, "First 70 chars at w10")
print(f"Overflow: '{CT73[70:]}'")

print(f"\nCT73[:70] at width 7:")
write_grid(CT73[:70], 7, "First 70 chars at w7")

# Check if the 3 overflow chars have special properties
print(f"\nOverflow chars: {CT73[70:]} = positions 70,71,72 = {[ALPH_IDX[c] for c in CT73[70:]]}")
print(f"These are the last 3 chars. In CT97, they correspond to positions near the end.")

# Check vertical bigrams in the 70-char block at widths 10 and 7
for w in [7, 10]:
    bgs = vertical_bigrams(CT73[:70], w)
    repeats = {bg: p for bg, p in bgs.items() if len(p) > 1}
    n_total = sum(len(p) for p in bgs.values())
    print(f"\nFirst 70 chars at width {w}: {len(repeats)} repeated bigrams out of {n_total} total")
    for bg, positions in sorted(repeats.items(), key=lambda x: -len(x[1])):
        print(f"  {bg} x{len(positions)}: at {positions}")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 7: COL7 INTERACTION — DESTROYED OR PRESERVED?
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 7: COL7 INTERACTION — PATTERN PRESERVATION")
print("=" * 70)

# We already know from prior results: col7 DESTROYS w10 (p=0.75) and w17 (p=0.63)
# Let's verify and analyze what this means structurally

print("Key finding from prior analysis:")
print("  CT73 width 10: p=0.006 (HIGH)")
print("  CT73_COL7 width 10: p=0.75 (NORMAL) -- DESTROYED by col7")
print("  CT73 width 17: p=0.008 (HIGH)")
print("  CT73_COL7 width 17: p=0.63 (NORMAL) -- DESTROYED by col7")
print()
print("INTERPRETATION: The width-10/17 patterns are properties of the CIPHER OUTPUT")
print("(before columnar transposition). The col7 transposition scrambles them.")
print()
print("This means: if the model is CT73 -> col7 decrypt -> inner cipher decrypt -> PT,")
print("then the inner cipher (operating on CT73_COL7) does NOT have periodic structure")
print("at widths 10 or 17. The patterns are ARTIFACTS of writing CT73_COL7 into")
print("7 columns and reading out as CT73.")

# Let's check: does APPLYING col7 to CT73 (i.e., col7 encrypt direction) preserve or create patterns?
CT73_COL7_ENC = apply_perm(CT73, COL7_PERM)  # Col7 encrypt direction
print(f"\nCT73_COL7 (decrypt direction, undo col7): {CT73_COL7}")
print(f"CT73_COL7_ENC (encrypt direction, apply col7): {CT73_COL7_ENC}")

for direction_name, text in [("COL7_DECRYPT", CT73_COL7), ("COL7_ENCRYPT", CT73_COL7_ENC)]:
    for w in [10, 17]:
        bgs = vertical_bigrams(text, w)
        repeats = {bg: p for bg, p in bgs.items() if len(p) > 1}
        n_rep = sum(len(p) for p in repeats.values())
        print(f"  {direction_name} width {w}: {len(repeats)} repeated bigram types, {n_rep} instances")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 8: WHAT MAKES WIDTH 10 SPECIAL? BIGRAM DETAILS
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 8: WIDTH-10 BIGRAM STRUCTURAL ANALYSIS")
print("=" * 70)

# Identify which specific bigrams repeat at width 10
bgs10 = vertical_bigrams(CT73, 10)
repeats10 = {bg: p for bg, p in bgs10.items() if len(p) > 1}

print(f"\nRepeated bigrams at width 10 ({len(repeats10)} types):")
for bg, positions in sorted(repeats10.items(), key=lambda x: -len(x[1])):
    for p in positions:
        # Check if either position is a crib position
        in_crib_top = p in CRIB_73
        in_crib_bot = (p + 10) in CRIB_73
        top_char = CT73[p]
        bot_char = CT73[p + 10]
        # Map back to CT97 positions
        ct97_map = [i for i in range(97) if i not in MASK_SET]
        p97_top = ct97_map[p] if p < len(ct97_map) else '?'
        p97_bot = ct97_map[p + 10] if (p + 10) < len(ct97_map) else '?'
        crib_mark = ""
        if in_crib_top:
            crib_mark += f" [TOP={CRIB_73[p]}]"
        if in_crib_bot:
            crib_mark += f" [BOT={CRIB_73[p+10]}]"
        print(f"  {bg}: pos {p} (CT97:{p97_top}) -> pos {p+10} (CT97:{p97_bot}){crib_mark}")

# Same for width 17
bgs17 = vertical_bigrams(CT73, 17)
repeats17 = {bg: p for bg, p in bgs17.items() if len(p) > 1}

print(f"\nRepeated bigrams at width 17 ({len(repeats17)} types):")
for bg, positions in sorted(repeats17.items(), key=lambda x: -len(x[1])):
    for p in positions:
        in_crib_top = p in CRIB_73
        in_crib_bot = (p + 17) in CRIB_73
        top_char = CT73[p]
        bot_char = CT73[p + 17]
        ct97_map = [i for i in range(97) if i not in MASK_SET]
        p97_top = ct97_map[p] if p < len(ct97_map) else '?'
        p97_bot = ct97_map[p + 17] if (p + 17) < len(ct97_map) else '?'
        crib_mark = ""
        if in_crib_top:
            crib_mark += f" [TOP={CRIB_73[p]}]"
        if in_crib_bot:
            crib_mark += f" [BOT={CRIB_73[p+17]}]"
        print(f"  {bg}: pos {p} (CT97:{p97_top}) -> pos {p+17} (CT97:{p97_bot}){crib_mark}")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 9: NON-STANDARD CIPHERS — QUAGMIRE, BIFID
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 9: QUAGMIRE II AND BIFID AT PERIODS 10/17")
print("=" * 70)

# Quagmire II: CT alphabet is keyword-mixed, PT alphabet is standard
# Each period position uses a different starting position in the CT alphabet
# Equivalent to: for position i, CT[i] = mixed_alph[(mixed_alph.index(PT[i]) + key[i%period]) % 26]

KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_IDX = {c: i for i, c in enumerate(KA)}

def decrypt_quagmire2(ct_text, key, ct_alphabet=KA):
    """Quagmire II: keyword CT alphabet, standard PT alphabet."""
    ct_idx = {c: i for i, c in enumerate(ct_alphabet)}
    period = len(key)
    result = []
    for i, c in enumerate(ct_text):
        ci = ct_idx[c]
        ki = key[i % period]
        pi = (ci - ki) % MOD
        result.append(ALPH[pi])
    return ''.join(result)

# Try Quagmire II with periods 10 and 17
for period in [10, 17]:
    print(f"\n--- Quagmire II (KA alphabet) period {period} ---")
    for variant_name, decrypt_fn in [
        ('Q2_KA', lambda ct, key: decrypt_quagmire2(ct, key, KA)),
    ]:
        # Extract key from crib positions
        key_constraints = defaultdict(set)
        for pos, pt_char in CRIB_73.items():
            r = pos % period
            ct_char = CT73[pos]
            # k = (KA_idx(ct) - AZ_idx(pt)) % 26
            ki = (KA_IDX[ct_char] - ALPH_IDX[pt_char]) % MOD
            key_constraints[r].add(ki)

        consistent = all(len(v) == 1 for v in key_constraints.values() if len(v) > 0)
        n_cons = sum(1 for v in key_constraints.values() if len(v) == 1)
        n_conflict = sum(1 for v in key_constraints.values() if len(v) > 1)

        print(f"  {variant_name}: {n_cons} consistent, {n_conflict} conflicting residues")

        # Build best key
        key = [0] * period
        for r, vals in key_constraints.items():
            if len(vals) == 1:
                key[r] = list(vals)[0]
            elif len(vals) > 1:
                key[r] = list(vals)[0]  # Pick first

        pt = decrypt_fn(CT73, key)
        crib = score_crib_match(pt, CRIB_73)
        qg = quadgram_score(pt)
        key_str = ''.join(ALPH[k] for k in key)
        print(f"    key={key_str}, crib={crib}/{len(CRIB_73)}, qg={qg:.3f}")
        print(f"    PT: {pt}")

# Bifid
def bifid_decrypt(ct_text, period, key_square=None):
    """Bifid cipher decryption with given period."""
    if key_square is None:
        # Use standard Polybius (merge I/J)
        key_square = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # 25 chars, J->I

    sq_idx = {}
    for i, c in enumerate(key_square):
        sq_idx[c] = (i // 5, i % 5)
    sq_idx['J'] = sq_idx.get('I', (1, 3))

    def char_to_rc(c):
        return sq_idx.get(c, (0, 0))

    def rc_to_char(r, c):
        idx = r * 5 + c
        if idx < len(key_square):
            return key_square[idx]
        return '?'

    # Bifid: split into blocks of period
    pt_chars = []
    ct_mapped = [c if c != 'J' else 'I' for c in ct_text]

    for block_start in range(0, len(ct_mapped), period):
        block = ct_mapped[block_start:block_start + period]
        rows = [char_to_rc(c)[0] for c in block]
        cols = [char_to_rc(c)[1] for c in block]

        # In Bifid encryption: rows then cols concatenated, then paired
        # Decryption: pair the row-col sequence, split back
        combined = rows + cols
        for i in range(len(block)):
            r = combined[i]
            c = combined[i + len(block)]
            pt_chars.append(rc_to_char(r, c))

    return ''.join(pt_chars)

# K4 has all 26 letters, so Bifid with 25-letter square needs J->I mapping
# But K4 CT has J... So Bifid is problematic. Test anyway.
print(f"\n--- Bifid at periods 10 and 17 ---")
for period in [10, 17]:
    pt = bifid_decrypt(CT73, period)
    crib = score_crib_match(pt, CRIB_73)
    qg = quadgram_score(pt)
    print(f"  Period {period}: crib={crib}/{len(CRIB_73)}, qg={qg:.3f}")
    print(f"    PT: {pt}")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 10: AUTOKEY ON CT73 (NOT CT73_COL7) AT PERIODS 10/17
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 10: AUTOKEY ON CT73 DIRECTLY (WITHOUT COL7)")
print("=" * 70)

# Previous autokey tests were on transposed text. If the bigram patterns
# at w10/w17 are in CT73 directly, maybe autokey works on CT73 directly.

# Exhaustive primer search for short primers (len 1-5) to warm up
print("\nExhaustive short primer autokey on CT73:")
best_overall = {'crib': 0, 'qg': -99.0}

for primer_len in [1, 2, 3]:
    best = {'crib': 0, 'qg': -99.0, 'info': ''}
    for primer_combo in itertools.product(range(26), repeat=primer_len):
        primer = list(primer_combo)
        for variant in ['vig', 'beau', 'vbeau']:
            for ak_type, ak_fn in [('pt', decrypt_autokey_pt), ('ct', decrypt_autokey_ct)]:
                pt = ak_fn(CT73, primer, variant)
                crib = score_crib_match(pt, CRIB_73)
                if crib > best['crib']:
                    qg = quadgram_score(pt)
                    best = {'crib': crib, 'qg': qg,
                            'info': f"primer={''.join(ALPH[p] for p in primer)}:{variant}:{ak_type}",
                            'pt': pt}
                    if crib > best_overall['crib']:
                        best_overall = dict(best)

    print(f"  Primer len {primer_len}: best crib={best['crib']}/{len(CRIB_73)}, qg={best['qg']:.3f}, {best['info']}")

# Also try thematic keywords as autokey primers on CT73
print("\nThematic keyword autokey on CT73:")
best = {'crib': 0, 'qg': -99.0, 'info': ''}
for word in sorted(set(THEMATIC)):
    if len(word) < 3 or len(word) > 30:
        continue
    primer = [ALPH_IDX[c] for c in word if c in ALPH_IDX]
    if not primer:
        continue
    for variant in ['vig', 'beau', 'vbeau']:
        for ak_type, ak_fn in [('pt', decrypt_autokey_pt), ('ct', decrypt_autokey_ct)]:
            pt = ak_fn(CT73, primer, variant)
            crib = score_crib_match(pt, CRIB_73)
            if crib > best['crib'] or (crib == best['crib'] and quadgram_score(pt) > best['qg']):
                qg = quadgram_score(pt)
                best = {'crib': crib, 'qg': qg,
                        'info': f"{word}:{variant}:{ak_type}", 'pt': pt}

print(f"  Best: crib={best['crib']}/{len(CRIB_73)}, qg={best['qg']:.3f}, {best['info']}")
if 'pt' in best:
    print(f"  PT: {best['pt']}")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 11: PERIOD-10/17 ON CT73_COL7 (INNER CIPHER TEXT)
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 11: PERIOD-10/17 CONSISTENCY ON CT73_COL7")
print("=" * 70)

# What do the cribs look like after col7?
# We need to track where crib positions move under col7 transposition
print("Crib positions after col7 transposition (inverse mapping):")

# If CT73 = col7_encrypt(inner_text), then inner_text = col7_decrypt(CT73) = CT73_COL7
# Crib position p in CT73 corresponds to position COL7_INV[p] in the inner text
CRIB_COL7 = {}
for p73, ch in CRIB_73.items():
    # After undoing col7, position p73 maps to COL7_INV[p73] in inner text
    p_inner = COL7_INV[p73]
    CRIB_COL7[p_inner] = ch

print(f"Crib positions in CT73_COL7: {sorted(CRIB_COL7.items())}")

for period in [10, 17]:
    print(f"\n--- Period {period} on CT73_COL7 ---")
    for variant in ['vig', 'beau', 'vbeau']:
        n_con, n_tot, details = check_period_consistency(CT73_COL7, CRIB_COL7, period, variant)
        conflicts = sum(1 for r, d in details.items() if d[0] == 'CONFLICT')
        print(f"  {variant}: {n_con}/{n_tot} consistent, {conflicts} conflicts")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 12: SERIATION — DO REPEATS CLUSTER?
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 12: SERIATION — REPEAT POSITION CLUSTERING")
print("=" * 70)

# For width 10: where do the repeated bigrams cluster?
print("\nWidth-10 repeated bigram position map (73 positions):")
map10 = ['.'] * CT73_LEN
for bg, positions in repeats10.items():
    for p in positions:
        map10[p] = bg[0].lower()  # Mark first char of bigram
        if p + 10 < CT73_LEN:
            map10[p + 10] = bg[1].lower()

# Also mark crib positions
crib_map = ['.'] * CT73_LEN
for p in CRIB_73:
    crib_map[p] = '^'

for row_start in range(0, CT73_LEN, 10):
    row_end = min(row_start + 10, CT73_LEN)
    ct_row = CT73[row_start:row_end]
    map_row = ''.join(map10[row_start:row_end])
    crib_row = ''.join(crib_map[row_start:row_end])
    print(f"  {row_start:2d}: {ct_row}  bigram:{map_row}  crib:{crib_row}")

print(f"\nWidth-17 repeated bigram position map:")
map17 = ['.'] * CT73_LEN
for bg, positions in repeats17.items():
    for p in positions:
        map17[p] = bg[0].lower()
        if p + 17 < CT73_LEN:
            map17[p + 17] = bg[1].lower()

for row_start in range(0, CT73_LEN, 17):
    row_end = min(row_start + 17, CT73_LEN)
    ct_row = CT73[row_start:row_end]
    map_row = ''.join(map17[row_start:row_end])
    crib_row = ''.join(crib_map[row_start:row_end])
    print(f"  {row_start:2d}: {ct_row}  bigram:{map_row}  crib:{crib_row}")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 13: MULTIPLE MASKS — SENSITIVITY ANALYSIS
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 13: SENSITIVITY — DO OTHER 15/24 MASKS SHOW SAME PATTERNS?")
print("=" * 70)

# From MEMORY.md: 6 distinct 15/24 masks share 17 consensus positions
# The 7 varying positions are in clusters: {38-45}, {55-56}, {87-88}, {93-96}
# Let's test a few alternate masks

CONSENSUS_NULLS = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
# The current mask adds: 38,39,40,55,88,94,96 (7 more to reach 24)
# Alternative: swap some varying positions
ALTERNATE_MASKS = [
    # Current
    sorted(list(CONSENSUS_NULLS) + [38,39,40,55,88,94,96]),
    # Alt 1: move 38->45, 39->56, 94->93
    sorted(list(CONSENSUS_NULLS) + [45,40,56,55,88,93,96]),
    # Alt 2: move 40->41, 55->56, 96->95
    sorted(list(CONSENSUS_NULLS) + [38,39,41,56,88,94,95]),
    # Alt 3: vary more
    sorted(list(CONSENSUS_NULLS) + [38,39,40,56,87,93,95]),
]

import random
random.seed(42)

# Also generate some random 24-null masks for comparison
for _ in range(3):
    non_crib = [i for i in range(97) if i not in {p for s, w in CRIB_WORDS for p in range(s, s+len(w))}]
    mask = sorted(random.sample(non_crib, 24))
    ALTERNATE_MASKS.append(mask)

for mask_idx, mask in enumerate(ALTERNATE_MASKS):
    mask_set = set(mask)
    ct_extracted = ''.join(CT[i] for i in range(97) if i not in mask_set)
    n = len(ct_extracted)

    # Check width 10 and 17
    for w in [10, 17]:
        bgs = vertical_bigrams(ct_extracted, w)
        repeats = {bg: p for bg, p in bgs.items() if len(p) > 1}
        n_reps = sum(len(p) for p in repeats.values())
        print(f"  Mask {mask_idx} ({n} chars) width {w}: {len(repeats)} types, {n_reps} instances")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 14: EXHAUSTIVE PERIOD-10 BEAUFORT ON CT73 (FULL 26^free)
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 14: TARGETED PERIOD-10 KEY RECOVERY")
print("=" * 70)

# For period 10, check exact constraints at each residue class
for variant in ['vig', 'beau', 'vbeau']:
    print(f"\n--- Period 10, {variant.upper()} ---")
    residue_detail = defaultdict(list)

    for pos, pt_char in sorted(CRIB_73.items()):
        r = pos % 10
        ct_char = CT73[pos]
        k = compute_keystream(ct_char, pt_char, variant)
        residue_detail[r].append({
            'pos': pos, 'ct': ct_char, 'pt': pt_char,
            'k': k, 'k_letter': ALPH[k]
        })

    n_consistent = 0
    n_constrained = 0
    for r in range(10):
        entries = residue_detail.get(r, [])
        if not entries:
            print(f"  r={r}: (no crib positions)")
            continue

        keys = set(e['k'] for e in entries)
        n_constrained += len(entries)
        status = "CONSISTENT" if len(keys) == 1 else f"CONFLICT ({len(keys)} values)"
        if len(keys) == 1:
            n_consistent += len(entries)

        detail = ', '.join(f"pos{e['pos']}:{e['ct']}/{e['pt']}=k{e['k']}({e['k_letter']})"
                          for e in entries)
        print(f"  r={r}: {status} — {detail}")

    print(f"  Total: {n_consistent}/{n_constrained} consistent")

# Same for period 17
for variant in ['vig', 'beau', 'vbeau']:
    print(f"\n--- Period 17, {variant.upper()} ---")
    residue_detail = defaultdict(list)

    for pos, pt_char in sorted(CRIB_73.items()):
        r = pos % 17
        ct_char = CT73[pos]
        k = compute_keystream(ct_char, pt_char, variant)
        residue_detail[r].append({
            'pos': pos, 'ct': ct_char, 'pt': pt_char,
            'k': k, 'k_letter': ALPH[k]
        })

    n_consistent = 0
    n_constrained = 0
    for r in range(17):
        entries = residue_detail.get(r, [])
        if not entries:
            print(f"  r={r}: (no crib positions)")
            continue

        keys = set(e['k'] for e in entries)
        n_constrained += len(entries)
        if len(keys) == 1:
            n_consistent += len(entries)
            status = "CONSISTENT"
        else:
            status = f"CONFLICT ({len(keys)} values)"

        detail = ', '.join(f"pos{e['pos']}:{e['ct']}/{e['pt']}=k{e['k']}({e['k_letter']})"
                          for e in entries)
        print(f"  r={r}: {status} — {detail}")

    print(f"  Total: {n_consistent}/{n_constrained} consistent")

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 15: MONTE CARLO SIGNIFICANCE WITH CORRECTED MULTIPLE TESTING
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 15: MONTE CARLO — CORRECTED SIGNIFICANCE")
print("=" * 70)

# We tested ~20 widths. Bonferroni correction: p_corrected = p * 20
# Width 10: p=0.006 * 20 = 0.12 (not significant after correction!)
# Width 17: p=0.008 * 20 = 0.16 (not significant after correction!)

print("Multiple testing correction (Bonferroni):")
print(f"  Width 10: raw p=0.006, corrected p=0.006*20={0.006*20:.3f}")
print(f"  Width 17: raw p=0.008, corrected p=0.008*20={0.008*20:.3f}")
print(f"  NEITHER is significant at alpha=0.05 after Bonferroni correction!")
print()
print("However, these are the two MOST significant widths in CT73.")
print("Let's compute false discovery rate (FDR) instead.")

# Gather all CT73 p-values from the prior analysis
ct73_pvalues = {
    7: 0.04199, 14: 0.68526, 21: 0.24717, 31: 0.70964,
    3: 0.85376, 5: 0.58962, 11: 0.45751, 13: 0.41440,
    24: 0.81773, 8: 0.95301, 9: 0.94779, 10: 0.00634,
    15: 0.66411, 17: 0.00822, 19: 0.10166, 23: 0.49516,
    26: 0.43010, 28: 0.38447, 29: 0.74327, 30: 1.00000
}

# Benjamini-Hochberg FDR
n_tests = len(ct73_pvalues)
sorted_p = sorted(ct73_pvalues.items(), key=lambda x: x[1])
print(f"\nBenjamini-Hochberg FDR (n={n_tests}):")
for rank, (width, p) in enumerate(sorted_p[:5], 1):
    bh_threshold = 0.05 * rank / n_tests
    significant = p <= bh_threshold
    print(f"  Rank {rank}: width={width}, p={p:.5f}, BH threshold={bh_threshold:.5f}, {'SIGNIFICANT' if significant else 'not significant'}")

# Also: run a fresh, targeted MC simulation for widths 10 and 17 on CT73
# with 100K trials for better p-value precision
print(f"\n--- Fresh Monte Carlo (100K trials) for widths 10 and 17 on CT73 ---")
random.seed(12345)
ct73_list = list(CT73)
ct73_len = len(ct73_list)

for target_width in [10, 17]:
    actual_bgs = vertical_bigrams(CT73, target_width)
    actual_repeats = sum(1 for bg, p in actual_bgs.items() if len(p) > 1)

    counts_ge = 0
    n_trials = 100000

    for trial in range(n_trials):
        shuffled = list(ct73_list)
        random.shuffle(shuffled)
        shuffled_text = ''.join(shuffled)
        bgs = vertical_bigrams(shuffled_text, target_width)
        n_reps = sum(1 for bg, p in bgs.items() if len(p) > 1)
        if n_reps >= actual_repeats:
            counts_ge += 1

    p_val = counts_ge / n_trials
    print(f"  Width {target_width}: actual repeats={actual_repeats}, MC p={p_val:.6f} ({counts_ge}/{n_trials})")

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("SUMMARY OF ALL INVESTIGATIONS")
print("=" * 70)

elapsed = time.time()
timestamp = datetime.now().isoformat()

results = {
    'timestamp': timestamp,
    'ct73': CT73,
    'ct73_col7': CT73_COL7,
    'mask': MASK,
    'crib_73_positions': {str(k): v for k, v in sorted(CRIB_73.items())},
    'ene_start_73': ENE_START_73,
    'bcl_start_73': BCL_START_73,
    'width_10_repeated_bigrams': {bg: pos for bg, pos in repeats10.items()},
    'width_17_repeated_bigrams': {bg: pos for bg, pos in repeats17.items()},
    'investigations_completed': 15,
}

results_path = '/home/cpatrick/kryptos/results/f_width10_17_deep_investigation.json'
with open(results_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"\nResults saved to {results_path}")
